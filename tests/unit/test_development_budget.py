from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from mmaudit.models.development_costs import DevelopmentCostError, DevelopmentCostPolicy
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostLedgerConfigurationError,
    CostReservationOverrunError,
    CostReservationStateError,
)
from mmaudit.orchestration.development_budget import (
    DevelopmentBudgetSession,
    DevelopmentCostUncertainError,
)
from tests.development_cost_support import development_case


def _session(
    tmp_path: Path, *, attempts: int = 2
) -> tuple[DevelopmentBudgetSession, AtomicCostLedger]:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "synthetic-development-ledger.json", cap_usd=Decimal("20")
    )
    policy = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("20"),
        per_attempt_budget_usd=Decimal("5"),
        maximum_attempts=attempts,
    )
    return DevelopmentBudgetSession(policy=policy, ledger=ledger), ledger


def test_development_reserves_before_usage_and_reconciles_known_cost(tmp_path: Path) -> None:
    session, ledger = _session(tmp_path)
    snapshot, body = development_case()
    first = session.reserve(endpoint_snapshot=snapshot, request_id="local-1", request_body=body)
    held = ledger.snapshot()
    assert held.active_reserved_usd == first.estimate.estimated_cost_per_attempt_usd
    assert held.spent_usd == 0
    assert held.entries[0].status is CostEntryStatus.RESERVED
    entry = session.reconcile(first, actual_cost_usd=Decimal("0.01"))
    assert entry.status is CostEntryStatus.RECONCILED
    assert ledger.snapshot().spent_usd == Decimal("0.01")
    second = session.reserve(
        endpoint_snapshot=snapshot, request_id="local-1", request_body=body, attempt=2
    )
    assert session.reconcile(second, actual_cost_usd=Decimal("0.02")).accounted_cost_usd == Decimal(
        "0.02"
    )
    assert ledger.snapshot().spent_usd == Decimal("0.03")


def test_pending_and_unknown_costs_block_new_calls_until_resolved(tmp_path: Path) -> None:
    session, ledger = _session(tmp_path)
    snapshot, body = development_case()
    first = session.reserve(endpoint_snapshot=snapshot, request_id="local-1", request_body=body)
    with pytest.raises(CostBudgetExceededError, match="settled"):
        session.reserve(endpoint_snapshot=snapshot, request_id="local-2", request_body=body)
    with pytest.raises(DevelopmentCostUncertainError):
        session.reconcile(first, actual_cost_usd=None)
    state = ledger.snapshot()
    assert state.entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert state.spent_usd == first.estimate.estimated_cost_per_attempt_usd
    with pytest.raises(CostBudgetExceededError, match="settled"):
        session.reserve(
            endpoint_snapshot=snapshot, request_id="local-1", request_body=body, attempt=2
        )
    restarted = DevelopmentBudgetSession(
        policy=first.estimate.policy,
        ledger=AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("20")),
    )
    with pytest.raises(CostBudgetExceededError, match="settled"):
        restarted.reserve(endpoint_snapshot=snapshot, request_id="after-restart", request_body=body)
    session.reconcile(first, actual_cost_usd=Decimal("0.01"))
    session.reserve(endpoint_snapshot=snapshot, request_id="local-1", request_body=body, attempt=2)


@pytest.mark.parametrize("actual", (Decimal("0.5"), Decimal("21")))
def test_actual_overrun_is_recorded_and_cannot_be_hidden_by_restart(
    tmp_path: Path, actual: Decimal
) -> None:
    session, ledger = _session(tmp_path)
    snapshot, body = development_case()
    first = session.reserve(endpoint_snapshot=snapshot, request_id="local-1", request_body=body)
    with pytest.raises(CostReservationOverrunError):
        session.reconcile(first, actual_cost_usd=actual)
    state = ledger.snapshot()
    assert state.spent_usd == actual
    assert state.has_reservation_overrun is True
    assert state.over_cap is (actual > Decimal("20"))
    reopened = DevelopmentBudgetSession(
        policy=first.estimate.policy,
        ledger=AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("20")),
    )
    with pytest.raises(CostBudgetExceededError, match="prior provider cost"):
        reopened.reserve(endpoint_snapshot=snapshot, request_id="after-restart", request_body=body)
    with pytest.raises(CostReservationOverrunError):
        session.reconcile(first, actual_cost_usd=actual)


def test_attempt_policy_duplicate_and_unknown_handles_fail_without_new_holds(
    tmp_path: Path,
) -> None:
    session, ledger = _session(tmp_path)
    snapshot, body = development_case()
    for attempt in (0, 3, True):
        with pytest.raises(DevelopmentCostError, match="retry policy"):
            session.reserve(
                endpoint_snapshot=snapshot, request_id="local-1", request_body=body, attempt=attempt
            )
    with pytest.raises(DevelopmentCostError, match="prior attempt"):
        session.reserve(
            endpoint_snapshot=snapshot, request_id="local-1", request_body=body, attempt=2
        )
    assert not ledger.snapshot().entries
    first = session.reserve(endpoint_snapshot=snapshot, request_id="local-1", request_body=body)
    with pytest.raises(CostReservationStateError, match="already recorded"):
        session.reserve(endpoint_snapshot=snapshot, request_id="local-1", request_body=body)
    with pytest.raises(CostReservationStateError, match="unknown or changed"):
        session.reconcile(replace(first, attempt=2), actual_cost_usd=Decimal("0.01"))
    with pytest.raises(DevelopmentCostError, match="exact Decimal"):
        session.reconcile(first, actual_cost_usd=0.01)  # type: ignore[arg-type]
    assert len(ledger.snapshot().entries) == 1


def test_target_mismatch_and_over_target_estimate_do_not_write_ledger(tmp_path: Path) -> None:
    _, ledger = _session(tmp_path)
    before = ledger.path.read_bytes()
    with pytest.raises(DevelopmentCostError, match="match the cumulative"):
        DevelopmentBudgetSession(
            policy=DevelopmentCostPolicy(
                overspend_risk_accepted=True,
                total_budget_usd=Decimal("10"),
                per_attempt_budget_usd=Decimal("1"),
            ),
            ledger=ledger,
        )
    tiny = DevelopmentBudgetSession(
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("20"),
            per_attempt_budget_usd=Decimal("0.01"),
        ),
        ledger=ledger,
    )
    snapshot, body = development_case()
    with pytest.raises(CostBudgetExceededError, match="budget targets"):
        tiny.reserve(endpoint_snapshot=snapshot, request_id="local-1", request_body=body)
    assert ledger.path.read_bytes() == before


def test_atomic_settled_cost_check_allows_only_one_concurrent_hold(tmp_path: Path) -> None:
    session, ledger = _session(tmp_path)
    snapshot, body = development_case()

    def reserve(request_id: str) -> bool:
        try:
            session.reserve(endpoint_snapshot=snapshot, request_id=request_id, request_body=body)
        except CostBudgetExceededError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(reserve, ("parallel-a", "parallel-b")))
    assert sorted(results) == [False, True]
    assert len(ledger.snapshot().entries) == 1


def test_existing_ledger_reservations_remain_unchanged_without_opt_in(tmp_path: Path) -> None:
    _, ledger = _session(tmp_path)
    first = ledger.reserve("ordinary-1", Decimal("1"))
    ledger.reconcile(first, None)
    second = ledger.reserve("ordinary-2", Decimal("1"))
    assert second.reserved_usd == Decimal("1")
    with pytest.raises(CostBudgetExceededError, match="settled"):
        ledger.reserve("development-3", Decimal("1"), require_settled_prior_costs=True)
    for value in (1, "true", None):
        with pytest.raises(CostLedgerConfigurationError, match="boolean"):
            ledger.reserve("invalid", Decimal("1"), require_settled_prior_costs=value)  # type: ignore[arg-type]
