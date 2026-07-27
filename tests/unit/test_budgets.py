from __future__ import annotations

import asyncio
from dataclasses import replace
from decimal import Decimal

import pytest

from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    BudgetReservationStateError,
    EndpointRequestCostBound,
    Reservation,
    UnprovenCostBoundError,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostReservationOverrunError,
)


def _manager(tmp_path, *, cap: str) -> tuple[BudgetManager, AtomicCostLedger]:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "model-cost-ledger.json",
        cap_usd=Decimal(cap),
    )
    return (
        BudgetManager(
            total_usd=float(cap),
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=10,
            atomic_ledger=ledger,
        ),
        ledger,
    )


def _endpoint_bound(
    request_material: str,
    *,
    prompt_units: int | None = None,
    completion_units: int = 10,
) -> EndpointRequestCostBound:
    return EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id="alpha/atlas-secure",
        provider_endpoint="approved-provider",
        request_material=request_material,
        pricing={
            "completion": "0.002",
            "prompt": "0.001",
            "request": "0.1",
        },
        maximum_units={
            "completion": completion_units,
            "prompt": (
                len(request_material.encode("utf-8")) if prompt_units is None else prompt_units
            ),
            "request": 1,
        },
    )


@pytest.mark.asyncio
async def test_budget_manager_persists_reservation_and_reconciliation(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.01")

    reservation = await manager.reserve("request-1", "review", "prompt")
    assert ledger.snapshot().active_reserved_usd == Decimal(str(reservation.estimated_cost_usd))

    accounted = await manager.reconcile(reservation, 0.00001)
    snapshot = ledger.snapshot()
    assert accounted == 0.00001
    assert snapshot.active_reserved_usd == Decimal(0)
    assert snapshot.spent_usd == Decimal("0.00001")


@pytest.mark.asyncio
async def test_concurrent_budget_reservations_cannot_cross_persistent_cap(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.000015")

    results = await asyncio.gather(
        manager.reserve("request-a", "review-a", "x"),
        manager.reserve("request-b", "review-b", "x"),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, BudgetExhaustedError) for result in results) == 1
    assert ledger.snapshot().active_reserved_usd <= Decimal("0.000015")


@pytest.mark.asyncio
async def test_pre_send_release_is_persisted_without_spend(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.01")
    reservation = await manager.reserve("request-1", "review", "prompt")

    await manager.release(reservation)

    snapshot = ledger.snapshot()
    assert snapshot.active_reserved_usd == Decimal(0)
    assert snapshot.spent_usd == Decimal(0)


@pytest.mark.asyncio
async def test_reconciliation_is_idempotent_and_cannot_change_cost(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.01")
    reservation = await manager.reserve("request-1", "review", "prompt")

    first = await manager.reconcile(reservation, 0.00001)
    second = await manager.reconcile(reservation, 0.00001)

    assert first == second == 0.00001
    assert manager.spent_usd == 0.00001
    assert ledger.snapshot().spent_usd == Decimal("0.00001")
    with pytest.raises(BudgetReservationStateError, match="different cost"):
        await manager.reconcile(reservation, 0.00002)


@pytest.mark.asyncio
async def test_repeated_overrun_does_not_double_count_spend(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.01")
    reservation = await manager.reserve("request-1", "review", "prompt")

    with pytest.raises(CostReservationOverrunError):
        await manager.reconcile(reservation, 0.001)
    with pytest.raises(CostReservationOverrunError):
        await manager.reconcile(reservation, 0.001)

    assert manager.spent_usd == 0.001
    assert ledger.snapshot().spent_usd == Decimal("0.001")


@pytest.mark.asyncio
async def test_unknown_or_tampered_reservation_cannot_mutate_accounting(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.01")
    reservation = await manager.reserve("request-1", "review", "prompt")
    forged = Reservation(
        identifier=reservation.identifier,
        estimated_cost_usd=reservation.estimated_cost_usd + 1,
        persistent=reservation.persistent,
    )

    with pytest.raises(BudgetReservationStateError, match="unknown or inconsistent"):
        await manager.reconcile(forged, 0.00001)
    with pytest.raises(BudgetReservationStateError, match="unknown or inconsistent"):
        await manager.release(forged)

    assert manager.spent_usd == 0
    assert ledger.snapshot().active_reserved_usd > 0


@pytest.mark.asyncio
async def test_reopened_manager_seeds_terminal_persistent_spend(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.01")
    reservation = await manager.reserve("request-1", "review", "prompt")
    await manager.reconcile(reservation, 0.00001)

    reopened = BudgetManager(
        total_usd=0.01,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )

    assert reopened.spent_usd == 0.00001
    assert reopened.remaining_usd == pytest.approx(0.00999)


@pytest.mark.asyncio
async def test_reopened_manager_fails_on_unrecovered_active_reservation(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.01")
    await manager.reserve("request-1", "review", "prompt")

    with pytest.raises(BudgetReservationStateError, match="explicit recovery"):
        BudgetManager(
            total_usd=0.01,
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=10,
            atomic_ledger=ledger,
        )


def test_certification_cost_bounds_require_a_durable_atomic_ledger() -> None:
    with pytest.raises(BudgetReservationStateError, match="durable atomic ledger"):
        BudgetManager(
            total_usd=1,
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=10,
            require_endpoint_cost_bound=True,
        )


@pytest.mark.asyncio
async def test_certification_refuses_missing_endpoint_cost_bound_before_reserving(
    tmp_path,
) -> None:
    manager, ledger = _manager(tmp_path, cap="1")
    manager.require_endpoint_cost_bound = True

    with pytest.raises(UnprovenCostBoundError, match="lacks an endpoint-bound"):
        await manager.reserve("request-1", "review", "serialized request")

    assert ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_endpoint_cost_bound_reserves_exact_component_maximum(tmp_path) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "certification-costs.json",
        cap_usd=Decimal("1"),
    )
    manager = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )

    reservation = await manager.reserve(
        "request-1",
        "review",
        request_material,
        endpoint_cost_bound=bound,
    )

    assert bound.maximum_cost_usd == Decimal("0.123000000000000000")
    assert reservation.estimated_cost_usd == 0.123
    assert reservation.endpoint_cost_bound == bound
    assert ledger.snapshot().active_reserved_usd == Decimal("0.123")


@pytest.mark.asyncio
async def test_endpoint_bound_must_match_request_and_token_ceilings(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="10")
    manager.require_endpoint_cost_bound = True

    with pytest.raises(UnprovenCostBoundError, match="serialized request"):
        await manager.reserve(
            "request-mismatch",
            "review",
            "different",
            endpoint_cost_bound=_endpoint_bound("original"),
        )
    with pytest.raises(UnprovenCostBoundError, match="UTF-8 byte"):
        await manager.reserve(
            "prompt-too-small",
            "review",
            "request",
            endpoint_cost_bound=_endpoint_bound("request", prompt_units=1),
        )
    with pytest.raises(UnprovenCostBoundError, match="configured output"):
        await manager.reserve(
            "completion-too-small",
            "review",
            "request",
            endpoint_cost_bound=_endpoint_bound("request", completion_units=9),
        )

    assert ledger.snapshot().entries == ()


def test_endpoint_pricing_proof_rejects_incomplete_or_inexact_material() -> None:
    with pytest.raises(ValueError, match="every endpoint pricing field"):
        EndpointRequestCostBound.from_endpoint_pricing(
            exact_model_id="alpha/atlas-secure",
            provider_endpoint="approved-provider",
            request_material="request",
            pricing={"prompt": "0.001", "completion": "0.002", "request": "0.1"},
            maximum_units={"prompt": 10, "completion": 10},
        )
    with pytest.raises(ValueError, match="decimal strings"):
        EndpointRequestCostBound.from_endpoint_pricing(
            exact_model_id="alpha/atlas-secure",
            provider_endpoint="approved-provider",
            request_material="request",
            pricing={
                "prompt": 0.001,  # type: ignore[dict-item]
                "completion": "0.002",
            },
            maximum_units={"prompt": 10, "completion": 10},
        )

    valid = _endpoint_bound("request")
    with pytest.raises(ValueError, match="snapshot hash"):
        replace(valid, pricing_snapshot_sha256="0" * 64)


@pytest.mark.asyncio
async def test_endpoint_bound_concurrency_cannot_cross_persistent_cap(tmp_path) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "certification-costs.json",
        cap_usd=Decimal("0.2"),
    )
    manager = BudgetManager(
        total_usd=0.2,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )

    results = await asyncio.gather(
        manager.reserve(
            "request-a",
            "review-a",
            request_material,
            endpoint_cost_bound=bound,
        ),
        manager.reserve(
            "request-b",
            "review-b",
            request_material,
            endpoint_cost_bound=bound,
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert sum(isinstance(result, BudgetExhaustedError) for result in results) == 1
    assert ledger.snapshot().active_reserved_usd == Decimal("0.123")
