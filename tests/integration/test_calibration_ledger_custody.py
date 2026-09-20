"""Local actual-ledger accounting, with provider access and secret loading prohibited."""

from decimal import Decimal
from pathlib import Path

import pytest

import mmaudit.orchestration.authenticated_calibration_accounting as accounting
from mmaudit.models.authenticated_runner import (
    _require_closed_cross_lineage_ledger_interval,
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
    require_verified_cross_lineage_runner_custody,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostReservationOverrunError,
    PortfolioAttemptSlot,
)
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit.test_calibration_ledger_accounting import closed_interval


@pytest.mark.parametrize("state", ("reserved", "unknown", "overrun", "ceiling", "held"))
def test_starting_scope_cannot_erase_or_waive_preexisting_liabilities(
    tmp_path: Path, forbid_network_and_secrets: list[str], state: str
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "prior.json", cap_usd=Decimal("250"))
    if state == "held":
        ledger.reserve_portfolio("a" * 64, (PortfolioAttemptSlot("held", Decimal("1")),))
    else:
        amount = Decimal("250") if state == "ceiling" else Decimal("1")
        reservation = ledger.reserve("prior", amount)
        if state == "unknown":
            ledger.commit_for_transport(reservation)
            ledger.reconcile(reservation, None)
        elif state == "overrun":
            with pytest.raises(CostReservationOverrunError):
                ledger.reconcile(reservation, Decimal("2"))
        elif state == "ceiling":
            ledger.reconcile(reservation, amount)
    original = ledger.path.read_bytes()
    with pytest.raises(ValueError):
        accounting.begin_calibration_ledger_accounting(ledger)
    assert ledger.path.read_bytes() == original
    assert forbid_network_and_secrets == []


def test_later_actual_bill_can_be_reconciled_without_promoting_an_unknown_reservation(
    tmp_path: Path, forbid_network_and_secrets: list[str]
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "actual.json", cap_usd=Decimal("250"))
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "first")
        )
        opened = begin_cross_lineage_ledger_interval(ledger)
        reservation = ledger.reserve("later", Decimal("1"))
        ledger.commit_for_transport(reservation)
        ledger.reconcile(reservation, None)
        unknown = accounting.observe_calibration_ledger_accounting(owner)
        assert accounting.CalibrationAccountingBlocker.UNKNOWN_BILLING in unknown.blockers
        with pytest.raises(ValueError, match="UNKNOWN_BILLING"):
            accounting.require_calibration_ledger_prefix(prefix)
        # This is a new synthetic actual bill supplied to the original ledger API,
        # not an accounting-owner estimate, automatic settlement or historical waiver.
        ledger.reconcile(reservation, Decimal("0.123456789"))
        closed = close_cross_lineage_ledger_interval(opened, expected_request_ids=("later",))
        accounting.retain_calibration_ledger_interval(owner, interval=closed)
        final = accounting.require_calibration_accounting_ready(owner)
        assert final.current_snapshot.spent_usd == Decimal("0.373456789")
        assert final.retained_request_count == 2
        assert accounting.require_calibration_ledger_prefix(prefix).ordinal == 1
        assert forbid_network_and_secrets == []


@pytest.mark.parametrize("later", ("known", "reserved", "unknown", "overrun", "ceiling", "held"))
def test_every_later_liability_is_visible_and_blocks_unassigned_or_unsafe_work(
    tmp_path: Path, forbid_network_and_secrets: list[str], later: str
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic.json", cap_usd=Decimal("250"))
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        original = closed_interval(ledger, "original")
        prefix = accounting.retain_calibration_ledger_interval(owner, interval=original)
        if later == "held":
            ledger.reserve_portfolio(
                "a" * 64,
                (PortfolioAttemptSlot(request_id="later", maximum_cost_usd=Decimal("1")),),
            )
        else:
            amount = Decimal("249.75") if later == "ceiling" else Decimal("1")
            reservation = ledger.reserve("later", amount)
            if later == "unknown":
                ledger.commit_for_transport(reservation)
                ledger.reconcile(reservation, None)
            elif later == "overrun":
                with pytest.raises(CostReservationOverrunError):
                    ledger.reconcile(reservation, Decimal("2"))
            elif later != "reserved":
                ledger.reconcile(reservation, amount)
        original_bytes = ledger.path.read_bytes()
        observed = accounting.observe_calibration_ledger_accounting(owner)
        assert accounting.CalibrationAccountingBlocker.UNASSIGNED_WORK in observed.blockers
        expected = {
            "reserved": accounting.CalibrationAccountingBlocker.ACTIVE_RESERVATIONS,
            "unknown": accounting.CalibrationAccountingBlocker.UNKNOWN_BILLING,
            "overrun": accounting.CalibrationAccountingBlocker.RESERVATION_OVERRUN,
            "ceiling": accounting.CalibrationAccountingBlocker.LEDGER_CEILING,
            "held": accounting.CalibrationAccountingBlocker.ACTIVE_PORTFOLIO_HOLDS,
        }.get(later)
        if expected is not None:
            assert expected in observed.blockers
            with pytest.raises(ValueError):
                accounting.require_calibration_ledger_prefix(prefix)
        else:
            assert accounting.require_calibration_ledger_prefix(prefix).ordinal == 1
        with pytest.raises(ValueError):
            accounting.require_calibration_accounting_ready(owner)
        with pytest.raises(ValueError):
            _require_closed_cross_lineage_ledger_interval(original)
        if later == "unknown":
            entry = next(
                item for item in observed.current_snapshot.entries if item.request_id == "later"
            )
            assert entry.actual_cost_usd is None
            assert entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
            assert entry.accounted_cost_usd == Decimal("1")
        assert ledger.path.read_bytes() == original_bytes
        assert forbid_network_and_secrets == []


def test_full_128_interval_accounting_uses_one_ledger_and_refuses_an_extra_capture(
    tmp_path: Path, forbid_network_and_secrets: list[str]
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "bounded.json", cap_usd=Decimal("250"))
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        retained = []
        for index in range(128):
            interval = closed_interval(ledger, f"synthetic-{index:03}", "0")
            retained.append(accounting.retain_calibration_ledger_interval(owner, interval=interval))
        original_bytes = ledger.path.read_bytes()
        observation = accounting.require_calibration_accounting_ready(owner)
        assert observation.retained_interval_count == observation.retained_request_count == 128
        assert len(observation.current_snapshot.entries) == 128
        assert accounting.require_calibration_ledger_prefix(retained[0]).ordinal == 1
        assert accounting.require_calibration_ledger_prefix(retained[-1]).ordinal == 128
        with pytest.raises(ValueError, match="bound reached"):
            accounting.retain_calibration_ledger_interval(owner, interval=interval)
        assert ledger.path.read_bytes() == original_bytes
        assert forbid_network_and_secrets == []


def test_cost_prefix_cannot_substitute_for_authenticated_runner_custody(
    tmp_path: Path, forbid_network_and_secrets: list[str]
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "cost-only.json", cap_usd=Decimal("250"))
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "synthetic")
        )
        with pytest.raises(ValueError, match="absent or mismatched"):
            require_verified_cross_lineage_runner_custody(prefix, evidence=None)  # type: ignore[arg-type]
        assert forbid_network_and_secrets == []
