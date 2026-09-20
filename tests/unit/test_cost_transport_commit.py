"""Synthetic regressions for the final durable spending transition."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from mmaudit.orchestration.budgets import (
    BudgetManager,
    BudgetReservationStateError,
    EndpointRequestCostBound,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostLedgerConfigurationError,
    CostReservation,
    CostReservationOverrunError,
    CostReservationStateError,
    PortfolioAttemptSlot,
    ReleaseReason,
)


@pytest.mark.parametrize("operation", ("claim", "adopt"))
@pytest.mark.parametrize("liability", ("unsent", "known", "unknown", "overrun", "ceiling"))
def test_known_cost_claim_and_adoption_stop_on_durable_liability(
    tmp_path: Path,
    operation: str,
    liability: str,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "held-liability.json", cap_usd=Decimal("250"))
    pending = ledger.reserve("pending", Decimal("1"))
    portfolio = ledger.reserve_portfolio("a" * 64, (PortfolioAttemptSlot("held", Decimal("1")),))
    prior = ledger.reserve("prior", Decimal("1"))
    if liability == "known":
        ledger.reconcile(prior, Decimal("0.5"))
    elif liability == "unknown":
        ledger.commit_for_transport(prior)
    elif liability in {"overrun", "ceiling"}:
        with pytest.raises(CostReservationOverrunError):
            ledger.reconcile(prior, Decimal("251") if liability == "ceiling" else Decimal("2"))
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    before = reopened.snapshot()

    def acquire() -> CostReservation | None:
        if operation == "adopt":
            return reopened.active_reservation("pending", require_known_prior_costs=True)
        return reopened.claim_portfolio_slot(
            portfolio, "held", Decimal("0.5"), require_known_prior_costs=True
        )

    if liability in {"unknown", "overrun", "ceiling"}:
        with pytest.raises(CostBudgetExceededError):
            acquire()
        assert reopened.snapshot() == before
    else:
        result = acquire()
        assert result is not None
        if operation == "adopt":
            assert result == pending
    # Historical read-only adoption retains its meaning, even after a cost stop.
    assert reopened.active_reservation("pending") == pending


@pytest.mark.parametrize("operation", ("claim", "adopt"))
def test_known_cost_claim_and_adoption_require_boolean_opt_in(
    tmp_path: Path,
    operation: str,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "typed-known-cost.json", cap_usd=Decimal("250"))
    portfolio = ledger.reserve_portfolio("a" * 64, (PortfolioAttemptSlot("held", Decimal("1")),))
    before = ledger.snapshot()
    with pytest.raises(CostLedgerConfigurationError, match="boolean"):
        if operation == "adopt":
            ledger.active_reservation("pending", require_known_prior_costs=1)
        else:
            ledger.claim_portfolio_slot(
                portfolio, "held", Decimal("0.5"), require_known_prior_costs=1
            )
    assert ledger.snapshot() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("actual", ("1.01", "250.01"))
async def test_preexisting_reservation_cannot_dispatch_after_another_call_overruns(
    tmp_path: Path, actual: str
) -> None:
    """Invariant: durable overrun blocks dispatch, not only new reservations."""

    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    manager = BudgetManager(
        total_usd=250,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    material = "synthetic non-deployable request"
    bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id="fixture/synthetic-model",
        provider_endpoint="synthetic-provider",
        request_material=material,
        pricing={"prompt": "0.001", "completion": "0.001"},
        maximum_units={"prompt": len(material.encode("utf-8")), "completion": 10},
    )
    pending = await manager.reserve(
        "synthetic-pending", "review", material, endpoint_cost_bound=bound
    )
    other = AtomicCostLedger.open_existing(path, cap_usd=Decimal("250"))
    first = other.reserve("synthetic-overrun", Decimal("1"))
    with pytest.raises(CostReservationOverrunError):
        other.reconcile(first, Decimal(actual))
    retained = path.read_bytes()

    with pytest.raises(CostBudgetExceededError, match="further calls are blocked"):
        await manager.commit_active_reservation_for_transport(pending)

    assert path.read_bytes() == retained
    assert ledger.active_reservation(pending.identifier) == pending.persistent
    assert manager._transport_committed == set()


@pytest.mark.parametrize("actual", ("0", "0.7", "1"))
def test_transport_commit_records_liability_then_exact_bill(tmp_path: Path, actual: str) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-attempt", Decimal("1"))
    identity = ledger.identity_sha256
    committed = ledger.commit_for_transport(pending)

    assert committed.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert committed.actual_cost_usd is None
    assert committed.accounted_cost_usd == committed.reserved_usd == Decimal("1")
    assert committed.reservation_id == pending.reservation_id
    assert ledger.snapshot().spent_usd == Decimal("1")
    assert ledger.snapshot().active_reserved_usd == 0
    assert ledger.snapshot().remaining_usd == Decimal("249")
    reopened = AtomicCostLedger.open_existing(path, cap_usd=Decimal("250"))
    assert reopened.identity_sha256 == identity
    assert reopened.snapshot().entries == (committed,)

    billed = reopened.reconcile(pending, Decimal(actual))
    assert billed.status is CostEntryStatus.RECONCILED
    assert billed.actual_cost_usd == billed.accounted_cost_usd == Decimal(actual)
    assert billed.reserved_usd == Decimal("1")


@pytest.mark.parametrize("terminal", ("committed", "unknown", "billed", "released"))
def test_nonreserved_attempt_never_receives_a_second_transport_commit(
    tmp_path: Path, terminal: str
) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-attempt", Decimal("1"))
    if terminal == "committed":
        ledger.commit_for_transport(pending)
    elif terminal == "unknown":
        ledger.reconcile(pending, None)
    elif terminal == "billed":
        ledger.reconcile(pending, Decimal("0.5"))
    else:
        ledger.release(pending, reason=ReleaseReason.CANCELLED_BEFORE_SEND)
    retained = path.read_bytes()
    reopened = AtomicCostLedger.open_existing(path, cap_usd=Decimal("250"))
    with pytest.raises(CostReservationStateError, match="not reserved for transport"):
        reopened.commit_for_transport(pending)
    assert path.read_bytes() == retained


def test_unknown_transport_cost_is_retained_and_cannot_be_released(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-attempt", Decimal("1"))
    committed = ledger.commit_for_transport(pending)
    assert ledger.reconcile(pending, None) == committed
    retained = path.read_bytes()
    with pytest.raises(CostReservationStateError, match="already finalized"):
        ledger.release(pending, reason=ReleaseReason.CANCELLED_BEFORE_SEND)
    with pytest.raises(CostBudgetExceededError, match="prior provider costs to be settled"):
        ledger.reserve("synthetic-next", Decimal("1"), require_settled_prior_costs=True)
    assert path.read_bytes() == retained


def test_cancelled_before_transport_releases_only_unused_reservation(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-costs.json", cap_usd=Decimal("1"))
    pending = ledger.reserve("synthetic-attempt", Decimal("1"))
    released = ledger.release(pending, reason=ReleaseReason.CANCELLED_BEFORE_SEND)
    assert released.status is CostEntryStatus.RELEASED
    assert released.actual_cost_usd is None
    assert released.accounted_cost_usd == 0
    assert ledger.snapshot().remaining_usd == Decimal("1")


@pytest.mark.parametrize("actual", ("1.01", "250.01"))
@pytest.mark.parametrize("claimed", (False, True))
def test_overrun_blocks_held_and_already_claimed_portfolio_slots(
    tmp_path: Path, actual: str, claimed: bool
) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    first = ledger.reserve("synthetic-first", Decimal("1"))
    hold = ledger.reserve_portfolio(
        "a" * 64,
        (PortfolioAttemptSlot(request_id="synthetic-held", maximum_cost_usd=Decimal("1")),),
    )
    pending = (
        ledger.claim_portfolio_slot(hold, "synthetic-held", Decimal("0.5")) if claimed else None
    )
    ledger.commit_for_transport(first)
    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(first, Decimal(actual))
    retained = path.read_bytes()
    reopened = AtomicCostLedger.open_existing(path, cap_usd=Decimal("250"))
    with pytest.raises(CostBudgetExceededError, match="further calls are blocked"):
        if pending is None:
            reopened.claim_portfolio_slot(hold, "synthetic-held", Decimal("0.5"))
        else:
            reopened.commit_for_transport(pending)
    assert path.read_bytes() == retained
    overrun = next(e for e in reopened.snapshot().entries if e.request_id == first.request_id)
    assert overrun.actual_cost_usd == overrun.accounted_cost_usd == Decimal(actual)
    assert overrun.status is CostEntryStatus.RESERVATION_OVERRUN


def test_already_reserved_last_budget_atom_can_commit_once(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-costs.json", cap_usd=Decimal("250"))
    first = ledger.reserve("synthetic-first", Decimal("249.999999999999999999"))
    last = ledger.reserve("synthetic-last", Decimal("0.000000000000000001"))
    ledger.commit_for_transport(first)
    ledger.reconcile(first, first.reserved_usd)
    assert ledger.snapshot().remaining_usd == 0
    committed = ledger.commit_for_transport(last)
    assert committed.accounted_cost_usd == last.reserved_usd
    assert ledger.snapshot().spent_usd == Decimal("250")
    with pytest.raises(CostBudgetExceededError):
        ledger.reserve("synthetic-next", last.reserved_usd)


def test_concurrent_commit_of_same_reservation_has_only_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-attempt", Decimal("1"))
    barrier = Barrier(2)

    def commit(_index: int) -> bool:
        reopened = AtomicCostLedger.open_existing(path, cap_usd=Decimal("250"))
        barrier.wait(timeout=5)
        try:
            reopened.commit_for_transport(pending)
        except CostReservationStateError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(commit, range(2)))
    assert sorted(results) == [False, True]
    assert ledger.snapshot().spent_usd == Decimal("1")
    assert len(ledger.snapshot().entries) == 1


@pytest.mark.parametrize("field", ("request_id", "reservation_id", "reserved_usd"))
def test_transport_commit_rejects_mismatched_reservation_without_mutation(
    tmp_path: Path, field: str
) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-attempt", Decimal("1"))
    replacement: str | Decimal = {
        "request_id": "synthetic-unknown",
        "reservation_id": "f" * 32,
        "reserved_usd": Decimal("0.5"),
    }[field]
    forged = replace(pending, **{field: replacement})
    retained = path.read_bytes()
    with pytest.raises(CostReservationStateError):
        ledger.commit_for_transport(forged)
    assert path.read_bytes() == retained


@pytest.mark.parametrize("value", (None, {}, object()))
def test_transport_commit_rejects_noncanonical_handle_type(tmp_path: Path, value: Any) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    retained = path.read_bytes()
    with pytest.raises(CostReservationStateError, match="handle type"):
        ledger.commit_for_transport(value)
    assert path.read_bytes() == retained


@pytest.mark.asyncio
@pytest.mark.parametrize("surface", ("class", "instance", "code"))
async def test_budget_transport_rejects_mutated_ledger_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    manager = BudgetManager(
        total_usd=250,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id="fixture/synthetic-model",
        provider_endpoint="synthetic-provider",
        request_material="synthetic",
        pricing={"prompt": "0.001", "completion": "0.001"},
        maximum_units={"prompt": 9, "completion": 10},
    )
    pending = await manager.reserve(
        "synthetic-pending", "review", "synthetic", endpoint_cost_bound=bound
    )
    retained = path.read_bytes()
    if surface == "code":
        monkeypatch.setattr(
            AtomicCostLedger.commit_for_transport, "__code__", (lambda *_args: None).__code__
        )
    else:
        subject = AtomicCostLedger if surface == "class" else ledger
        monkeypatch.setattr(subject, "commit_for_transport", lambda *_args: None)
    with pytest.raises(BudgetReservationStateError, match="callable provenance"):
        await manager.commit_active_reservation_for_transport(pending)
    assert path.read_bytes() == retained


def test_failed_transport_commit_write_does_not_create_a_success_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-attempt", Decimal("1"))
    retained = path.read_bytes()

    def fail_write(_state: Any) -> None:
        raise OSError("synthetic local write failure")

    monkeypatch.setattr(ledger, "_write_state", fail_write)
    with pytest.raises(OSError, match="synthetic local write failure"):
        ledger.commit_for_transport(pending)
    assert path.read_bytes() == retained
    assert ledger.active_reservation(pending.request_id) == pending


def test_committed_actual_bill_is_still_recorded_after_other_call_overruns(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    first = ledger.reserve("synthetic-first", Decimal("1"))
    other = ledger.reserve("synthetic-other", Decimal("1"))
    ledger.commit_for_transport(first)
    ledger.commit_for_transport(other)
    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(first, Decimal("250.01"))
    settled = ledger.reconcile(other, Decimal("0.4"))
    assert settled.actual_cost_usd == settled.accounted_cost_usd == Decimal("0.4")
    assert ledger.snapshot().spent_usd == Decimal("250.41")
    assert ledger.snapshot().over_cap is True


def test_transport_commit_rejects_reservation_subclass(tmp_path: Path) -> None:
    class UntrustedReservation(CostReservation):
        pass

    path = tmp_path / "synthetic-costs.json"
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-attempt", Decimal("1"))
    untrusted = UntrustedReservation(
        request_id=pending.request_id,
        reservation_id=pending.reservation_id,
        reserved_usd=pending.reserved_usd,
    )
    retained = path.read_bytes()
    with pytest.raises(CostReservationStateError, match="handle type"):
        ledger.commit_for_transport(untrusted)
    assert path.read_bytes() == retained
