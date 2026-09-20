"""Cost-only custody over genuine disposable ledgers, never provider or audit credit."""

import copy
import gc
import json
import pickle
import weakref
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

import pytest

import mmaudit.orchestration.authenticated_calibration_accounting as accounting
from mmaudit.models.authenticated_runner import (
    ClosedCrossLineageLedgerInterval,
    _require_closed_cross_lineage_ledger_interval,
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostLedgerError,
    PortfolioAttemptSlot,
)


@pytest.fixture
def ledger(tmp_path: Path) -> AtomicCostLedger:
    return AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))


def closed_interval(
    ledger: AtomicCostLedger, request_id: str, actual: str = "0.25"
) -> ClosedCrossLineageLedgerInterval:
    opened = begin_cross_lineage_ledger_interval(ledger)
    reservation = ledger.reserve(request_id, Decimal("1"))
    ledger.reconcile(reservation, Decimal(actual))
    return close_cross_lineage_ledger_interval(opened, expected_request_ids=(request_id,))


def test_exact_prior_prefix_survives_later_append_without_reviving_old_closure(
    ledger: AtomicCostLedger,
) -> None:
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        first = closed_interval(ledger, "synthetic-z")
        prefix = accounting.retain_calibration_ledger_interval(owner, interval=first)
        original = accounting.require_calibration_ledger_prefix(prefix)
        assert accounting.require_calibration_accounting_ready(owner).blockers == ()

        second = closed_interval(ledger, "synthetic-a")
        with pytest.raises(ValueError, match="ledger changed after closure"):
            _require_closed_cross_lineage_ledger_interval(first)
        current = accounting.require_calibration_ledger_prefix(prefix)
        assert current.final_snapshot_sha256 == original.final_snapshot_sha256
        assert current.interval_request_ids == ("synthetic-z",)
        assert current.current_accounting.current_snapshot.spent_usd == Decimal("0.5")
        assert current.current_accounting.unassigned_request_ids == ("synthetic-a",)
        with pytest.raises(ValueError, match="UNASSIGNED_WORK"):
            accounting.require_calibration_accounting_ready(owner)
        retained_second = accounting.retain_calibration_ledger_interval(owner, interval=second)
        assert accounting.require_calibration_ledger_prefix(retained_second).ordinal == 2
        final = accounting.require_calibration_accounting_ready(owner)
        assert final.retained_interval_count == 2 and final.retained_request_count == 2
        assert not any(
            (
                final.serialized_authority,
                final.provider_call_authorized,
                final.runner_custody_authorized,
                final.model_qualification_authorized,
            )
        )
    with pytest.raises(ValueError, match="absent or revoked"):
        accounting.require_calibration_ledger_prefix(prefix)


@pytest.mark.parametrize("cap", ("1", "249.99", "250.01", "1000"))
def test_accounting_never_accepts_a_different_ledger_ceiling(tmp_path: Path, cap: str) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "wrong-cap.json", cap_usd=Decimal(cap))
    with pytest.raises(ValueError, match="exact bounds"):
        accounting.begin_calibration_ledger_accounting(ledger)


def test_known_baseline_is_counted_once_without_becoming_a_new_interval(
    ledger: AtomicCostLedger,
) -> None:
    closed_interval(ledger, "baseline", "0.5")
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "new", "0.25")
        )
        observed = accounting.require_calibration_accounting_ready(owner)
        assert observed.current_snapshot.spent_usd == Decimal("0.75")
        assert observed.retained_interval_count == observed.retained_request_count == 1
        assert accounting.require_calibration_ledger_prefix(prefix).interval_spent_usd == Decimal(
            "0.25"
        )


def test_a_new_handle_for_the_same_path_cannot_duplicate_ownership(
    ledger: AtomicCostLedger,
) -> None:
    with accounting.calibration_ledger_accounting_scope(ledger):
        same_ledger = AtomicCostLedger(ledger.path, cap_usd=Decimal("250"))
        with pytest.raises(ValueError, match="already has an owner"):
            accounting.begin_calibration_ledger_accounting(same_ledger)


@pytest.mark.parametrize("change", ("delete", "slot", "timestamp"))
def test_every_retained_portfolio_hold_field_remains_bound(
    ledger: AtomicCostLedger, change: str
) -> None:
    slots = (PortfolioAttemptSlot("never-sent", Decimal("1")),)
    hold = ledger.reserve_portfolio("a" * 64, slots)
    ledger.release_portfolio(hold, expected_remaining_slots=slots)
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "first")
        )
        payload = json.loads(ledger.path.read_text())
        held = payload["portfolio_holds"]["a" * 64]
        if change == "delete":
            payload["portfolio_holds"].pop("a" * 64)
        elif change == "slot":
            held["slots"][0]["maximum_cost_usd"] = "2"
        else:
            held["updated_at"] = held["created_at"]
        ledger.path.write_text(json.dumps(payload))
        with pytest.raises((ValueError, CostLedgerError)):
            accounting.require_calibration_ledger_prefix(prefix)


def test_external_mutation_of_a_projection_cannot_change_retained_cost_state(
    ledger: AtomicCostLedger,
) -> None:
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "first")
        )
        projected = accounting.require_calibration_ledger_prefix(prefix)
        object.__setattr__(projected, "interval_spent_usd", Decimal("0"))
        object.__setattr__(
            projected.current_accounting.current_snapshot.entries[0],
            "actual_cost_usd",
            Decimal("0"),
        )
        fresh = accounting.require_calibration_ledger_prefix(prefix)
        assert fresh.interval_spent_usd == Decimal("0.25")
        assert fresh.current_accounting.current_snapshot.entries[0].actual_cost_usd == Decimal(
            "0.25"
        )


def test_capture_cannot_start_after_its_exact_closure_already_became_stale(
    ledger: AtomicCostLedger,
) -> None:
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        stale = closed_interval(ledger, "first")
        closed_interval(ledger, "later")
        with pytest.raises(ValueError, match="ledger changed after closure"):
            accounting.retain_calibration_ledger_interval(owner, interval=stale)
        assert accounting.observe_calibration_ledger_accounting(owner).retained_interval_count == 0


@pytest.mark.parametrize("kind", ("duplicate", "gap", "foreign-ledger", "unissued"))
def test_capture_requires_one_contiguous_original_ledger_history(
    ledger: AtomicCostLedger, tmp_path: Path, kind: str
) -> None:
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        first = closed_interval(ledger, "first")
        accounting.retain_calibration_ledger_interval(owner, interval=first)
        if kind == "duplicate":
            rejected = first
        elif kind == "gap":
            closed_interval(ledger, "omitted")
            rejected = closed_interval(ledger, "after-gap")
        elif kind == "foreign-ledger":
            other = AtomicCostLedger.initialize(tmp_path / "other.json", cap_usd=Decimal("250"))
            rejected = closed_interval(other, "other")
        else:
            rejected = object.__new__(ClosedCrossLineageLedgerInterval)
        with pytest.raises(ValueError):
            accounting.retain_calibration_ledger_interval(owner, interval=rejected)
        assert accounting.observe_calibration_ledger_accounting(owner).retained_interval_count == 1


@pytest.mark.parametrize("change", ("delete", "cost", "reservation", "identity"))
def test_altered_prefix_or_ledger_identity_cannot_be_accepted(
    ledger: AtomicCostLedger, change: str
) -> None:
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "first")
        )
        if change == "identity":
            ledger.lock_path.rename(ledger.lock_path.with_suffix(".retained-test-lock"))
        else:
            payload = json.loads(ledger.path.read_text())
            entry = payload["entries"]["first"]
            if change == "delete":
                payload["entries"].pop("first")
            elif change == "cost":
                entry["actual_cost_usd"] = entry["accounted_cost_usd"] = "0.2"
            else:
                entry["reserved_usd"] = "2"
            ledger.path.write_text(json.dumps(payload))
        retained = ledger.path.read_bytes()
        with pytest.raises((ValueError, CostLedgerError)):
            accounting.require_calibration_ledger_prefix(prefix)
        with pytest.raises((ValueError, CostLedgerError)):
            accounting.observe_calibration_ledger_accounting(owner)
        assert ledger.path.read_bytes() == retained


@pytest.mark.parametrize("operation", (copy.copy, copy.deepcopy, pickle.dumps))
def test_neither_owner_nor_prefix_can_be_copied_or_serialized(
    ledger: AtomicCostLedger, operation: Any
) -> None:
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "first")
        )
        for capability in (owner, prefix):
            with pytest.raises(TypeError):
                operation(capability)


@pytest.mark.parametrize(
    "capability_type",
    (accounting.CalibrationLedgerAccounting, accounting.RetainedCalibrationLedgerPrefix),
)
def test_direct_and_unregistered_objects_never_recreate_cost_custody(capability_type: Any) -> None:
    with pytest.raises(TypeError):
        capability_type()
    fake = object.__new__(capability_type)
    with pytest.raises(ValueError):
        accounting.observe_calibration_ledger_accounting(fake)
    with pytest.raises(ValueError):
        accounting.require_calibration_ledger_prefix(fake)


def test_a_ledger_has_one_owner_and_closed_ownership_cannot_be_revived(
    ledger: AtomicCostLedger,
) -> None:
    owner = accounting.begin_calibration_ledger_accounting(ledger)
    with pytest.raises(ValueError, match="already has an owner"):
        accounting.begin_calibration_ledger_accounting(ledger)
    accounting.close_calibration_ledger_accounting(owner)
    with pytest.raises(ValueError, match="absent or revoked"):
        accounting.close_calibration_ledger_accounting(owner)
    with accounting.calibration_ledger_accounting_scope(ledger) as successor:
        assert successor is not owner
        with pytest.raises(ValueError, match="absent or revoked"):
            accounting.observe_calibration_ledger_accounting(owner)


def test_forgetting_owner_invalidates_prefix_and_releases_single_owner_slot(
    ledger: AtomicCostLedger,
) -> None:
    owner = accounting.begin_calibration_ledger_accounting(ledger)
    prefix = accounting.retain_calibration_ledger_interval(
        owner, interval=closed_interval(ledger, "first")
    )
    reference = weakref.ref(owner)
    del owner
    gc.collect()
    assert reference() is None
    with pytest.raises(ValueError, match="absent or revoked"):
        accounting.require_calibration_ledger_prefix(prefix)
    with accounting.calibration_ledger_accounting_scope(ledger):
        pass


@pytest.mark.parametrize("fault", (ValueError, RuntimeError, KeyboardInterrupt))
def test_scope_error_revokes_all_cost_receipts(ledger: AtomicCostLedger, fault: Any) -> None:
    with pytest.raises(fault), accounting.calibration_ledger_accounting_scope(ledger) as owner:
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "first")
        )
        raise fault("synthetic local consumer failure")
    with pytest.raises(ValueError, match="absent or revoked"):
        accounting.require_calibration_ledger_prefix(prefix)


def test_low_ambient_decimal_precision_cannot_round_retained_actual_cost(
    ledger: AtomicCostLedger,
) -> None:
    with accounting.calibration_ledger_accounting_scope(ledger) as owner:
        closed = closed_interval(ledger, "precise", "0.123456789")
        with localcontext() as context:
            context.prec = 3
            prefix = accounting.retain_calibration_ledger_interval(owner, interval=closed)
            assert accounting.require_calibration_ledger_prefix(
                prefix
            ).interval_spent_usd == Decimal("0.123456789")


@pytest.mark.parametrize(
    "binding", ("_CAP", "CalibrationLedgerAccounting", "close_calibration_ledger_accounting")
)
def test_scope_disposal_precedes_reporting_runtime_binding_drift(
    ledger: AtomicCostLedger, monkeypatch: pytest.MonkeyPatch, binding: str
) -> None:
    with (
        monkeypatch.context() as context,
        pytest.raises(ValueError, match="not pristine"),
        accounting.calibration_ledger_accounting_scope(ledger) as owner,
    ):
        prefix = accounting.retain_calibration_ledger_interval(
            owner, interval=closed_interval(ledger, "first")
        )
        context.setattr(accounting, binding, object())
    with pytest.raises(ValueError, match="absent or revoked"):
        accounting.require_calibration_ledger_prefix(prefix)
