"""Exact two-row policy relaxation and atomic stop checks using only synthetic ledgers."""

import json
from dataclasses import replace
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.legacy_cost_allowance import (
    LegacyUncertainCostAllowance,
    LegacyUncertainCostEntry,
)
from mmaudit.models.route_constraints import RouteCostReservationPolicy
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostLedgerConfigurationError,
    CostPriorBillingUnknownError,
    CostReservationOverrunError,
    PortfolioAttemptSlot,
    unknown_prior_billing_entries,
)
from tests.legacy_cost_support import seed_legacy_uncertainty


@pytest.fixture
def legacy_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[AtomicCostLedger, LegacyUncertainCostAllowance]:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    return ledger, seed_legacy_uncertainty(ledger, monkeypatch)


def test_legacy_policy_keeps_exact_bytes_and_new_policy_retains_all_other_rules(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance],
) -> None:
    _, allowance = legacy_ledger
    legacy = RouteCostReservationPolicy.build()
    assert (
        legacy.policy_sha256 == "2c5580e2bf08a047aaa70d887062515fdf283697ff3f4a547e5c9fae53d5962a"
    )
    assert "legacy_uncertain_allowance" not in legacy.model_dump(mode="json")
    current = RouteCostReservationPolicy.build(legacy_uncertain_allowance=allowance)
    assert current.schema_version == "1.1" and current.unknown_billing_blocks_new_work is True
    assert current.legacy_uncertain_allowance == allowance
    excluded = {"schema_version", "legacy_uncertain_allowance", "policy_sha256"}
    assert current.model_dump(exclude=excluded) == legacy.model_dump(exclude=excluded)
    assert RouteCostReservationPolicy.model_validate_json(current.model_dump_json()) == current
    assert current.policy_sha256 != legacy.policy_sha256


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("request_id", "authrunner.smoke.r18.judge.replay:" + "1" * 64),
        ("request_id", "authrunner.smoke.r17.judge.replay:" + "1" * 64 + ":attempt:2"),
        ("request_id", "authrunner.smoke.r17.judge.replay"),
        ("reservation_id", "short"),
        ("reserved_usd_exact", "0.05225616"),
        ("accounted_cost_usd_exact", "0.05225616"),
        ("actual_cost_usd", "0.18105"),
        ("status", "reconciled"),
        ("release_reason", "cancelled_before_send"),
        ("created_at", "2026-09-11T00:00:00+00:00"),
        ("updated_at", "2026-09-09T00:00:00+00:00"),
        ("updated_at", "2026-08-20T00:00:00+00:00"),
        ("created_at", "2026-08-24T12:00:00"),
        ("created_at", "2026-08-24T12:00:00+01:00"),
    ),
)
def test_allowance_refuses_other_future_settled_or_differently_priced_rows(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance], field: str, value: Any
) -> None:
    _, allowance = legacy_ledger
    payload = allowance.entries[0].model_dump(mode="json") | {field: value}
    with pytest.raises(ValidationError):
        LegacyUncertainCostEntry.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("alteration", ("reversed", "duplicate", "hash", "forged_nested"))
def test_allowance_requires_the_exact_pair_and_revalidates_nested_bindings(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance], alteration: str
) -> None:
    ledger, allowance = legacy_ledger
    if alteration == "reversed":
        with pytest.raises(ValidationError):
            LegacyUncertainCostAllowance.build(tuple(reversed(allowance.entries)))
    elif alteration == "duplicate":
        with pytest.raises(ValidationError):
            LegacyUncertainCostAllowance.build((allowance.entries[0], allowance.entries[0]))
    else:
        changed = allowance.model_copy(
            update={"allowance_sha256": "0" * 64}
            if alteration == "hash"
            else {
                "entries": (
                    allowance.entries[0].model_copy(update={"reserved_usd_exact": "1"}),
                    allowance.entries[1],
                )
            }
        )
        original = ledger.path.read_bytes()
        with pytest.raises(CostLedgerConfigurationError):
            ledger.reserve(
                "prohibited",
                Decimal("1"),
                require_known_prior_costs=True,
                legacy_uncertain_allowance=changed,
            )
        with pytest.raises(ValueError):
            RouteCostReservationPolicy.build(legacy_uncertain_allowance=changed)
        assert ledger.path.read_bytes() == original


@pytest.mark.parametrize(
    "field",
    (
        "request_id",
        "reservation_id",
        "created_at",
        "updated_at",
        "reserved_usd",
        "accounted_cost_usd",
    ),
)
def test_exact_matching_never_accepts_a_changed_historical_identity_or_liability(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance], field: str
) -> None:
    ledger, allowance = legacy_ledger
    entry = next(item for item in ledger.snapshot().entries if ".r17." in item.request_id)
    original_value = getattr(entry, field)
    changed_value = (
        original_value + timedelta(seconds=1)
        if isinstance(original_value, datetime)
        else original_value + Decimal("0.00000001")
        if isinstance(original_value, Decimal)
        else original_value[:-1] + ("2" if original_value[-1] != "2" else "3")
    )
    changed = replace(entry, **{field: changed_value})
    assert unknown_prior_billing_entries((changed,), legacy_uncertain_allowance=allowance) == (
        changed,
    )
    assert unknown_prior_billing_entries((entry,), legacy_uncertain_allowance=allowance) == ()


def _operation(ledger: AtomicCostLedger, operation: str, allowance: Any) -> Any:
    options = dict(require_known_prior_costs=True, legacy_uncertain_allowance=allowance)
    if operation == "reserve":
        return ledger.reserve("next", Decimal("0.01"), **options)
    if operation == "claim":
        hold = ledger.snapshot().portfolio_holds[0].as_reservation()
        return ledger.claim_portfolio_slot(hold, "held", Decimal("0.01"), **options)
    if operation == "adopt":
        return ledger.active_reservation("pending", **options)
    pending = ledger.active_reservation("pending")
    assert pending is not None
    return ledger.commit_for_transport(pending, **options)


@pytest.mark.parametrize("operation", ("reserve", "claim", "adopt", "commit"))
@pytest.mark.parametrize("reopen", (False, True))
def test_each_atomic_boundary_preserves_historical_rows_and_their_full_charge(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance],
    operation: str,
    reopen: bool,
) -> None:
    ledger, allowance = legacy_ledger
    original_entries = ledger.snapshot().entries
    ledger.reserve("pending", Decimal("0.01"))
    ledger.reserve_portfolio("a" * 64, (PortfolioAttemptSlot("held", Decimal("0.01")),))
    if reopen:
        ledger = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    retained = ledger.path.read_bytes()
    with pytest.raises(CostPriorBillingUnknownError):
        _operation(ledger, operation, None)
    assert ledger.path.read_bytes() == retained
    assert _operation(ledger, operation, allowance) is not None
    after = ledger.snapshot()
    by_id = {entry.request_id: entry for entry in after.entries}
    assert tuple(by_id[entry.request_id] for entry in original_entries) == original_entries
    assert all(entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED for entry in original_entries)
    assert after.spent_usd >= Decimal("0.23330616")
    assert after.remaining_usd <= Decimal("249.76669384")


@pytest.mark.parametrize("operation", ("reserve", "claim", "adopt", "commit"))
@pytest.mark.parametrize("extra", ("unlisted", "lookalike", "future_same_scope"))
def test_other_or_future_uncertain_rows_block_every_atomic_boundary_without_writes(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance], operation: str, extra: str
) -> None:
    ledger, allowance = legacy_ledger
    ledger.reserve("pending", Decimal("0.01"))
    ledger.reserve_portfolio("a" * 64, (PortfolioAttemptSlot("held", Decimal("0.01")),))
    identifier = (
        "unlisted-uncertain"
        if extra == "unlisted"
        else "authrunner.smoke.r17.judge.replay:" + "2" * 64
        if extra == "future_same_scope"
        else "authrunner.smoke.r17.judge.replay:" + "1" * 64 + ":attempt:2"
    )
    prior = ledger.reserve(identifier, Decimal("0.18105"))
    ledger.commit_for_transport(prior)
    retained = ledger.path.read_bytes()
    with pytest.raises(CostPriorBillingUnknownError):
        _operation(ledger, operation, allowance)
    assert ledger.path.read_bytes() == retained


@pytest.mark.parametrize("operation", ("reserve", "claim", "adopt", "commit"))
def test_explicit_allowance_cannot_be_mixed_with_legacy_unchecked_mode(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance], operation: str
) -> None:
    ledger, allowance = legacy_ledger
    pending = ledger.reserve("pending", Decimal("0.01"))
    hold = ledger.reserve_portfolio("a" * 64, (PortfolioAttemptSlot("held", Decimal("0.01")),))
    before = ledger.path.read_bytes()
    options = dict(legacy_uncertain_allowance=allowance)
    with pytest.raises(CostLedgerConfigurationError):
        if operation == "reserve":
            ledger.reserve("next", Decimal("0.01"), **options)
        elif operation == "claim":
            ledger.claim_portfolio_slot(hold, "held", Decimal("0.01"), **options)
        elif operation == "adopt":
            ledger.active_reservation("pending", **options)
        else:
            ledger.commit_for_transport(pending, **options)
    assert ledger.path.read_bytes() == before


def test_allowed_uncertainty_still_reduces_available_ceiling(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance],
) -> None:
    ledger, allowance = legacy_ledger
    before = ledger.path.read_bytes()
    with pytest.raises(CostBudgetExceededError):
        ledger.reserve(
            "cannot-forget-history",
            Decimal("250"),
            require_known_prior_costs=True,
            legacy_uncertain_allowance=allowance,
        )
    assert ledger.path.read_bytes() == before


@pytest.mark.parametrize("operation", ("reserve", "claim", "adopt", "commit"))
@pytest.mark.parametrize("actual", ("1.01", "250.01"))
def test_exact_legacy_allowance_never_waives_an_overrun_or_the_global_ceiling(
    legacy_ledger: tuple[AtomicCostLedger, LegacyUncertainCostAllowance],
    operation: str,
    actual: str,
) -> None:
    ledger, allowance = legacy_ledger
    ledger.reserve("pending", Decimal("0.01"))
    ledger.reserve_portfolio("a" * 64, (PortfolioAttemptSlot("held", Decimal("0.01")),))
    other = ledger.reserve("overrun", Decimal("1"))
    with pytest.raises(CostReservationOverrunError):
        ledger.reconcile(other, Decimal(actual))
    retained = ledger.path.read_bytes()
    with pytest.raises(CostBudgetExceededError) as caught:
        _operation(ledger, operation, allowance)
    assert not isinstance(caught.value, CostPriorBillingUnknownError)
    assert ledger.path.read_bytes() == retained
