from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from decimal import Decimal, localcontext
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import mmaudit.orchestration.budgets as budgets_module
from mmaudit.config import ModelRetryPolicy
from mmaudit.models.schemas import (
    ContextRequestEvidence,
    ModelRequestValidationStatus,
    UsageRecord,
)
from mmaudit.models.usage import is_recovery_accountable_usage_record
from mmaudit.orchestration.budgets import (
    AtomicRequestLimitReservationEvidence,
    AtomicTokenReservationEvidence,
    BudgetExhaustedError,
    BudgetManager,
    BudgetReservationStateError,
    EndpointRequestCostBound,
    PortfolioTaskSlot,
    Reservation,
    TokenReservationOverrunError,
    UnprovenCostBoundError,
    _issue_trusted_budget_recovery_scope,
    _issue_trusted_request_limit_scope,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostReservationOverrunError,
    ReleaseReason,
)
from tests.unit.test_usage import (
    _creditable_record,
    _retry_token_bound_creditable_record,
    _token_plan_for_record,
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


def _portfolio_slot(
    bound: EndpointRequestCostBound,
    *,
    task_id: str = "task-a",
    logical_request_id: str = "request-a",
    attempt_ordinal: int = 1,
    maximum_cost_usd: str = "0.2",
) -> PortfolioTaskSlot:
    request_id = (
        logical_request_id
        if attempt_ordinal == 1
        else f"{logical_request_id}:attempt:{attempt_ordinal}"
    )
    return PortfolioTaskSlot(
        task_id=task_id,
        logical_request_id=logical_request_id,
        attempt_ordinal=attempt_ordinal,
        request_id=request_id,
        role="review",
        exact_model_id=bound.exact_model_id,
        provider_endpoint=bound.provider_endpoint,
        endpoint_policy_snapshot_sha256="a" * 64,
        endpoint_policy_pricing_sha256="b" * 64,
        endpoint_pricing_snapshot_sha256=bound.pricing_snapshot_sha256,
        envelope_recipe_sha256="c" * 64,
        planned_prompt_tokens=bound.maximum_units_for("prompt"),
        planned_visible_output_tokens=8,
        planned_reasoning_tokens=2,
        planned_completion_tokens=10,
        maximum_cost_usd=Decimal(maximum_cost_usd),
    )


def _portfolio_manager(
    tmp_path, *, input_tokens: int = 20
) -> tuple[BudgetManager, AtomicCostLedger]:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "portfolio-cost-ledger.json",
        cap_usd=Decimal("1"),
    )
    return (
        BudgetManager(
            total_usd=1,
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=2,
            atomic_ledger=ledger,
            require_endpoint_cost_bound=True,
            global_input_token_budget=input_tokens,
            global_output_token_budget=40,
            per_model_usd_caps={"alpha/atlas-secure": "1"},
            per_role_usd_caps={"review": "1"},
        ),
        ledger,
    )


def _shared_recovery_usage(
    request_id: str,
    *,
    root_scope: str,
    count_before: int,
    maximum: int = 10,
    cost_usd_exact: str = "0.01",
) -> UsageRecord:
    base = _creditable_record()
    exact_cost = Decimal(cost_usd_exact)
    record = base.model_copy(
        update={
            "request_id": request_id,
            "reported_cost_usd": float(exact_cost),
            "reported_cost_usd_exact": format(exact_cost, "f"),
            "accounted_cost_usd": float(exact_cost),
            "accounted_cost_usd_exact": format(exact_cost, "f"),
            "user_prompt_sha256": base.prompt_sha256,
        }
    )
    plan, token = _token_plan_for_record(record, request_id=request_id)
    assert record.user_prompt_sha256 is not None
    context = ContextRequestEvidence.build(
        request_id=request_id,
        request_role=record.role,
        context_role=record.role,
        byte_budget=256,
        declared_bytes_used=32,
        rendered_bytes=32,
        source_bytes=16,
        configured_maximum_source_tokens_per_request=64,
        effective_source_byte_ceiling=128,
        rendered_sha256=record.user_prompt_sha256,
    )
    request_limit = AtomicRequestLimitReservationEvidence.build(
        request_id=request_id,
        exact_model_id=record.requested_model,
        role=record.role,
        request_token_plan_sha256=plan.plan_sha256,
        request_limit_scope=root_scope,
        request_limit_count_before=count_before,
        request_limit_maximum=maximum,
    )
    recovered = record.model_copy(
        update={
            "routing": {
                **record.routing,
                "context_request_evidence": context.model_dump(mode="json"),
                "context_request_evidence_sha256": context.evidence_sha256,
                "request_token_plan": plan.model_dump(mode="json"),
                "request_token_plan_sha256": plan.plan_sha256,
                "atomic_token_reservations": [token.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [token.evidence_sha256],
                "atomic_token_reservation": token.model_dump(mode="json"),
                "atomic_token_reservation_sha256": token.evidence_sha256,
                "atomic_request_limit_reservations": [request_limit.model_dump(mode="json")],
                "atomic_request_limit_reservation_sha256s": [request_limit.evidence_sha256],
                "atomic_request_limit_reservation": request_limit.model_dump(mode="json"),
                "atomic_request_limit_reservation_sha256": request_limit.evidence_sha256,
            }
        }
    )
    assert is_recovery_accountable_usage_record(
        recovered,
        request_limit_scope=root_scope,
        request_limit_count_before=count_before,
    )
    return recovered


def _released_recovery_usage(
    request_id: str,
    *,
    root_scope: str,
    count_before: int,
    maximum: int,
) -> UsageRecord:
    """Build exact failed pre-send usage retaining request and token custody."""

    base = _shared_recovery_usage(
        request_id,
        root_scope=root_scope,
        count_before=count_before,
        maximum=maximum,
        cost_usd_exact="0",
    )
    released = UsageRecord.model_validate(
        base.model_copy(
            update={
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "cached_tokens": 0,
                "reasoning_tokens": 0,
                "reasoning_evidence": None,
                "token_detail_accounting_evidence": None,
                "reported_cost_usd": None,
                "reported_cost_usd_exact": None,
                "provider_error_classification": "timeout",
                "validation_status": ModelRequestValidationStatus.PROVIDER_ERROR,
                "status": "provider_error",
            }
        ).model_dump(mode="python")
    )
    assert is_recovery_accountable_usage_record(
        released,
        request_limit_scope=root_scope,
        request_limit_count_before=count_before,
    )
    return released


def _recovery_manager(
    tmp_path,
    records: tuple[UsageRecord, ...],
) -> tuple[BudgetManager, AtomicCostLedger]:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "shared-recovery-cost-ledger.json",
        cap_usd=Decimal("1"),
    )
    for record in records:
        reservation = ledger.reserve(record.request_id, Decimal("0.10"))
        assert record.reported_cost_usd_exact is not None
        ledger.reconcile(reservation, Decimal(record.reported_cost_usd_exact))
    return (_budget_manager_for_recovery_ledger(ledger), ledger)


def _recovered_no_usage_attempt(
    request_id: str,
    *,
    logical_request_id: str,
    status: str = "released_proven_pre_send",
    request_limit_scope: str | None,
    count_before: int | None,
    count_after: int | None,
    maximum: int | None,
    reserved_cost_usd_exact: Decimal = Decimal("0.10"),
) -> SimpleNamespace:
    return SimpleNamespace(
        request_id=request_id,
        logical_request_id=logical_request_id,
        task_id=f"task-{request_id}",
        requested_model="author/exact-model",
        role="source_audit",
        status=SimpleNamespace(value=status),
        reserved_cost_usd_exact=reserved_cost_usd_exact,
        accounted_cost_usd_exact=Decimal(0),
        request_limit_scope=request_limit_scope,
        request_limit_count_before=count_before,
        request_limit_count_after=count_after,
        request_limit_maximum=maximum,
    )


def _budget_manager_for_recovery_ledger(ledger: AtomicCostLedger) -> BudgetManager:
    return BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        global_input_token_budget=100_000,
        global_output_token_budget=10_000,
    )


def test_budget_constructor_canonicalizes_exact_integer_rates_and_rejects_subclasses() -> None:
    manager = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=2,
    )
    assert type(manager.total_usd) is float
    assert type(manager.conservative_rate) is float
    assert type(manager.max_output_tokens) is int
    assert type(manager.max_requests_per_agent) is int

    class FloatSubclass(float):
        pass

    with pytest.raises(ValueError, match="exact int or float"):
        BudgetManager(
            total_usd=FloatSubclass(1),
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=2,
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
async def test_reopened_manager_blocks_dispatch_until_active_reservation_recovery(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="0.01")
    await manager.reserve("request-1", "review", "prompt")

    reopened = BudgetManager(
        total_usd=0.01,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    assert reopened.recovery_required
    with pytest.raises(BudgetReservationStateError, match="exact usage recovery"):
        await reopened.reserve("request-2", "review", "prompt")


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
async def test_active_request_cost_ceiling_rejects_before_ledger_and_is_reusable(
    tmp_path,
) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "active-request-cost-ceiling.json",
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

    async with manager.active_request_cost_ceiling(Decimal("0.122999999999999999")):
        with pytest.raises(BudgetExhaustedError, match="active per-request cost ceiling"):
            await asyncio.create_task(
                manager.reserve(
                    "request-1",
                    "review",
                    request_material,
                    endpoint_cost_bound=bound,
                )
            )

    assert ledger.snapshot().entries == ()
    assert manager.reserved_usd == 0

    async with manager.active_request_cost_ceiling(Decimal("0.123")):
        reservation = await manager.reserve(
            "request-1",
            "review",
            request_material,
            endpoint_cost_bound=bound,
        )
    await manager.release(reservation)

    snapshot = ledger.snapshot()
    assert len(snapshot.entries) == 1
    assert snapshot.active_reserved_usd == 0
    assert snapshot.spent_usd == 0


@pytest.mark.asyncio
async def test_active_request_cost_ceiling_rejects_nested_scope_and_cleans_up(
    tmp_path,
) -> None:
    manager, ledger = _manager(tmp_path, cap="1")

    with pytest.raises(RuntimeError, match="callback failed"):
        async with manager.active_request_cost_ceiling(Decimal("0.01")):
            with pytest.raises(BudgetReservationStateError, match="already installed"):
                async with manager.active_request_cost_ceiling(Decimal("0.02")):
                    pass
            raise RuntimeError("callback failed")

    async with manager.active_request_cost_ceiling(Decimal("0.01")):
        reservation = await manager.reserve("request-after-cleanup", "review", "prompt")
    await manager.release(reservation)

    assert len(ledger.snapshot().entries) == 1


@pytest.mark.asyncio
async def test_active_request_cost_ceiling_rejects_stale_child_task_then_reuses(
    tmp_path,
) -> None:
    manager, ledger = _manager(tmp_path, cap="1")
    continue_after_scope = asyncio.Event()

    async def delayed_reserve() -> Reservation:
        await continue_after_scope.wait()
        return await manager.reserve("delayed-request", "review", "prompt")

    async with manager.active_request_cost_ceiling(Decimal("0.01")):
        delayed = asyncio.create_task(delayed_reserve())

    continue_after_scope.set()
    with pytest.raises(BudgetReservationStateError, match="inherited an inactive"):
        await delayed
    assert ledger.snapshot().entries == ()

    async with manager.active_request_cost_ceiling(Decimal("0.01")):
        reservation = await manager.reserve("delayed-request", "review", "prompt")
    await manager.release(reservation)

    assert len(ledger.snapshot().entries) == 1


@pytest.mark.asyncio
async def test_active_request_cost_ceiling_rejects_foreign_task_before_ledger(
    tmp_path,
) -> None:
    manager, ledger = _manager(tmp_path, cap="1")
    reserve_during_scope = asyncio.Event()

    async def foreign_reserve() -> Reservation:
        await reserve_during_scope.wait()
        return await manager.reserve("foreign-request", "review", "prompt")

    foreign = asyncio.create_task(foreign_reserve())
    async with manager.active_request_cost_ceiling(Decimal("0.01")):
        reserve_during_scope.set()
        with pytest.raises(BudgetReservationStateError, match="outside the active"):
            await foreign

    assert ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_active_request_cost_ceiling_is_trusted_accounting_state(tmp_path) -> None:
    manager, ledger = _manager(tmp_path, cap="1")

    with pytest.raises(BudgetReservationStateError, match="changed outside a trusted"):
        async with manager.active_request_cost_ceiling(Decimal("0.01")):
            manager._active_request_cost_ceiling_scope = None
            await manager.reserve("tamper-request", "review", "prompt")

    assert ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_portfolio_claims_conserve_durable_and_scoped_accounting_concurrently(
    tmp_path,
) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    manager, ledger = _portfolio_manager(tmp_path)
    slots = (
        _portfolio_slot(bound),
        _portfolio_slot(
            bound,
            task_id="task-b",
            logical_request_id="request-b",
        ),
    )
    portfolio = await manager.reserve_portfolio("d" * 64, slots)

    assert manager.reserved_usd == 0.4
    assert manager.reserved_input_tokens == 6
    assert manager.reserved_output_tokens == 20
    assert manager.reserved_model_usd(bound.exact_model_id) == Decimal("0.4")
    assert manager.reserved_role_usd("review") == Decimal("0.4")
    assert ledger.snapshot().entries == ()
    assert ledger.snapshot().active_reserved_usd == Decimal("0.4")

    with pytest.raises(BudgetReservationStateError, match="outside an active portfolio"):
        await manager.reserve(
            "request-a",
            "review",
            request_material,
            endpoint_cost_bound=bound,
            exact_model_id=bound.exact_model_id,
            planned_prompt_tokens=3,
            planned_visible_output_tokens=8,
            planned_reasoning_tokens=2,
            planned_completion_tokens=10,
            request_token_plan_sha256="e" * 64,
            request_limit_scope=_issue_trusted_request_limit_scope("request-a"),
        )

    async def claim(slot: PortfolioTaskSlot, plan_hash: str) -> Reservation:
        async with manager.portfolio_task_scope(portfolio, slot.task_id) as scoped:
            assert scoped == slot
            return await manager.reserve(
                slot.request_id,
                slot.role,
                request_material,
                endpoint_cost_bound=bound,
                exact_model_id=slot.exact_model_id,
                planned_prompt_tokens=3,
                planned_visible_output_tokens=8,
                planned_reasoning_tokens=2,
                planned_completion_tokens=10,
                request_token_plan_sha256=plan_hash,
                request_limit_scope=_issue_trusted_request_limit_scope(slot.logical_request_id),
            )

    reservations = await asyncio.gather(
        claim(slots[0], "e" * 64),
        claim(slots[1], "f" * 64),
    )

    assert manager.reserved_usd == float(bound.maximum_cost_usd * 2)
    assert manager.reserved_input_tokens == 6
    assert manager.reserved_output_tokens == 20
    assert manager.reserved_model_usd(bound.exact_model_id) == bound.maximum_cost_usd * 2
    assert manager.reserved_role_usd("review") == bound.maximum_cost_usd * 2
    assert ledger.snapshot().held_portfolio_usd == 0
    assert ledger.snapshot().active_reserved_usd == bound.maximum_cost_usd * 2
    assert {entry.request_id for entry in ledger.snapshot().entries} == {
        "request-a",
        "request-b",
    }

    await manager.release_portfolio(portfolio)
    with pytest.raises(BudgetReservationStateError, match="already finalized"):
        await manager.release_portfolio(portfolio)
    await asyncio.gather(*(manager.release(reservation) for reservation in reservations))
    assert manager.reserved_usd == 0
    assert ledger.snapshot().active_reserved_usd == 0


@pytest.mark.asyncio
async def test_portfolio_task_scope_allows_ordered_retries_and_failed_validation_is_atomic(
    tmp_path,
) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    manager, ledger = _portfolio_manager(tmp_path)
    first_slot = _portfolio_slot(bound)
    second_slot = _portfolio_slot(bound, attempt_ordinal=2)
    portfolio = await manager.reserve_portfolio("e" * 64, (first_slot, second_slot))
    held_bytes = ledger.path.read_bytes()

    async with manager.portfolio_task_scope(portfolio, first_slot.task_id):
        with pytest.raises(BudgetReservationStateError, match="identity, role, or model"):
            await manager.reserve(
                first_slot.request_id,
                "wrong-role",
                request_material,
                endpoint_cost_bound=bound,
                exact_model_id=first_slot.exact_model_id,
                planned_prompt_tokens=3,
                planned_visible_output_tokens=8,
                planned_reasoning_tokens=2,
                planned_completion_tokens=10,
                request_token_plan_sha256="f" * 64,
                request_limit_scope=_issue_trusted_request_limit_scope(
                    first_slot.logical_request_id
                ),
            )
        assert ledger.path.read_bytes() == held_bytes
        first = await manager.reserve(
            first_slot.request_id,
            first_slot.role,
            request_material,
            endpoint_cost_bound=bound,
            exact_model_id=first_slot.exact_model_id,
            planned_prompt_tokens=3,
            planned_visible_output_tokens=8,
            planned_reasoning_tokens=2,
            planned_completion_tokens=10,
            request_token_plan_sha256="f" * 64,
            request_limit_scope=_issue_trusted_request_limit_scope(first_slot.logical_request_id),
        )
        first_claim_bytes = ledger.path.read_bytes()
        with pytest.raises(BudgetReservationStateError, match="previous attempt is still active"):
            await manager.reserve(
                second_slot.request_id,
                second_slot.role,
                request_material,
                endpoint_cost_bound=bound,
                exact_model_id=second_slot.exact_model_id,
                planned_prompt_tokens=3,
                planned_visible_output_tokens=8,
                planned_reasoning_tokens=2,
                planned_completion_tokens=10,
                request_token_plan_sha256="1" * 64,
                request_limit_scope=_issue_trusted_request_limit_scope(
                    second_slot.logical_request_id
                ),
            )
        assert ledger.path.read_bytes() == first_claim_bytes
        await manager.release(first)
        with pytest.raises(BudgetReservationStateError, match="token ceilings"):
            await manager.reserve(
                second_slot.request_id,
                second_slot.role,
                request_material,
                endpoint_cost_bound=bound,
                exact_model_id=second_slot.exact_model_id,
                planned_prompt_tokens=3,
                planned_visible_output_tokens=9,
                planned_reasoning_tokens=1,
                planned_completion_tokens=10,
                request_token_plan_sha256="f" * 64,
                request_limit_scope=_issue_trusted_request_limit_scope(
                    second_slot.logical_request_id
                ),
            )
        second = await manager.reserve(
            second_slot.request_id,
            second_slot.role,
            request_material,
            endpoint_cost_bound=bound,
            exact_model_id=second_slot.exact_model_id,
            planned_prompt_tokens=3,
            planned_visible_output_tokens=8,
            planned_reasoning_tokens=2,
            planned_completion_tokens=10,
            request_token_plan_sha256="1" * 64,
            request_limit_scope=_issue_trusted_request_limit_scope(second_slot.logical_request_id),
        )
        with pytest.raises(BudgetReservationStateError, match="no remaining exact attempt"):
            await manager.reserve(
                "request-a:attempt:3",
                second_slot.role,
                request_material,
                endpoint_cost_bound=bound,
                exact_model_id=second_slot.exact_model_id,
                planned_prompt_tokens=3,
                planned_visible_output_tokens=8,
                planned_reasoning_tokens=2,
                planned_completion_tokens=10,
                request_token_plan_sha256="2" * 64,
                request_limit_scope=_issue_trusted_request_limit_scope(
                    second_slot.logical_request_id
                ),
            )
    assert second.persistent is not None
    assert ledger.snapshot().portfolio_holds[0].claimed_slots == tuple(
        slot.as_cost_slot() for slot in (first_slot, second_slot)
    )
    await manager.release(second)
    await manager.release_portfolio(portfolio)


@pytest.mark.asyncio
async def test_portfolio_cost_and_aggregate_cap_failures_are_atomic(tmp_path) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    manager, ledger = _portfolio_manager(tmp_path, input_tokens=5)
    slots = (
        _portfolio_slot(bound),
        _portfolio_slot(
            bound,
            task_id="task-b",
            logical_request_id="request-b",
        ),
    )
    legacy_bytes = ledger.path.read_bytes()

    with pytest.raises(BudgetExhaustedError, match="input-token"):
        await manager.reserve_portfolio("f" * 64, slots)
    assert ledger.path.read_bytes() == legacy_bytes
    assert manager.reserved_usd == 0

    cost_root = tmp_path / "cost"
    cost_root.mkdir(mode=0o700)
    manager, ledger = _portfolio_manager(cost_root)
    costly_slot = _portfolio_slot(bound, maximum_cost_usd="0.12")
    portfolio = await manager.reserve_portfolio("f" * 64, (costly_slot,))
    held_bytes = ledger.path.read_bytes()
    async with manager.portfolio_task_scope(portfolio, costly_slot.task_id):
        with pytest.raises(BudgetExhaustedError, match="cost ceiling"):
            await manager.reserve(
                costly_slot.request_id,
                costly_slot.role,
                request_material,
                endpoint_cost_bound=bound,
                exact_model_id=costly_slot.exact_model_id,
                planned_prompt_tokens=3,
                planned_visible_output_tokens=8,
                planned_reasoning_tokens=2,
                planned_completion_tokens=10,
                request_token_plan_sha256="1" * 64,
                request_limit_scope=_issue_trusted_request_limit_scope(
                    costly_slot.logical_request_id
                ),
            )
    assert ledger.path.read_bytes() == held_bytes
    assert ledger.snapshot().held_portfolio_usd == Decimal("0.12")


@pytest.mark.asyncio
async def test_portfolio_claim_shrinks_to_the_durable_endpoint_ceiling(tmp_path) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    manager, ledger = _portfolio_manager(tmp_path)
    slots = (
        _portfolio_slot(bound),
        _portfolio_slot(bound, attempt_ordinal=2),
    )
    portfolio = await manager.reserve_portfolio("0" * 64, slots)

    async with manager.portfolio_task_scope(portfolio, slots[0].task_id):
        first = await manager.reserve(
            slots[0].request_id,
            slots[0].role,
            request_material,
            endpoint_cost_bound=bound,
            exact_model_id=slots[0].exact_model_id,
            planned_prompt_tokens=3,
            planned_visible_output_tokens=8,
            planned_reasoning_tokens=2,
            planned_completion_tokens=10,
            request_token_plan_sha256="1" * 64,
            request_limit_scope=_issue_trusted_request_limit_scope(slots[0].logical_request_id),
        )
        assert first.persistent is not None
        assert first.persistent.reserved_usd == bound.maximum_cost_usd
        assert ledger.snapshot().active_reserved_usd == (
            slots[1].maximum_cost_usd + bound.maximum_cost_usd
        )
        with pytest.raises(CostReservationOverrunError):
            await manager.reconcile(first, Decimal("0.15"))
        held_after_overrun = ledger.path.read_bytes()
        with pytest.raises(BudgetExhaustedError, match="persistent model-cost budget"):
            await manager.reserve(
                slots[1].request_id,
                slots[1].role,
                request_material,
                endpoint_cost_bound=bound,
                exact_model_id=slots[1].exact_model_id,
                planned_prompt_tokens=3,
                planned_visible_output_tokens=8,
                planned_reasoning_tokens=2,
                planned_completion_tokens=10,
                request_token_plan_sha256="2" * 64,
                request_limit_scope=_issue_trusted_request_limit_scope(slots[1].logical_request_id),
            )
        assert ledger.path.read_bytes() == held_after_overrun
    assert ledger.snapshot().has_reservation_overrun


@pytest.mark.asyncio
async def test_portfolio_recovery_reinstalls_exact_held_and_pending_attempts(tmp_path) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    manager, ledger = _portfolio_manager(tmp_path)
    slots = (
        _portfolio_slot(bound),
        _portfolio_slot(
            bound,
            task_id="task-b",
            logical_request_id="request-b",
        ),
    )
    portfolio = await manager.reserve_portfolio("1" * 64, slots)
    ledger.claim_portfolio_slot(
        portfolio.persistent,
        slots[0].request_id,
        bound.maximum_cost_usd,
    )

    reopened = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
        global_input_token_budget=20,
        global_output_token_budget=40,
        per_model_usd_caps={"alpha/atlas-secure": "1"},
        per_role_usd_caps={"review": "1"},
    )
    assert reopened.recovery_required
    recovered = await reopened.recover_portfolio("1" * 64, slots)

    assert await reopened.recover_portfolio("1" * 64, slots) is recovered
    assert reopened.reserved_usd == float(slots[1].maximum_cost_usd + bound.maximum_cost_usd)
    assert reopened.reserved_input_tokens == 6
    assert reopened.reserved_output_tokens == 20
    assert reopened.recovery_required
    with pytest.raises(BudgetReservationStateError, match="exact recovery"):
        async with reopened.portfolio_task_scope(recovered, slots[1].task_id):
            pass
    recovered_attempt = SimpleNamespace(
        request_id=slots[0].request_id,
        logical_request_id=slots[0].logical_request_id,
        task_id=slots[0].task_id,
        requested_model=slots[0].exact_model_id,
        role=slots[0].role,
        status=SimpleNamespace(value="adopted_proven_pre_send"),
        reserved_cost_usd_exact=bound.maximum_cost_usd,
        accounted_cost_usd_exact=Decimal(0),
        request_limit_scope=slots[0].logical_request_id,
        request_limit_count_before=0,
        request_limit_count_after=1,
        request_limit_maximum=2,
    )
    recovery_scope = _issue_trusted_budget_recovery_scope(
        (),
        non_usage_attempts=(recovered_attempt,),
    )
    await reopened.restore_recovered_usage((), recovery_scope=recovery_scope)
    assert not reopened.recovery_required

    async with reopened.portfolio_task_scope(recovered, slots[0].task_id):
        adopted = await reopened.reserve(
            slots[0].request_id,
            slots[0].role,
            request_material,
            endpoint_cost_bound=bound,
            exact_model_id=slots[0].exact_model_id,
            planned_prompt_tokens=3,
            planned_visible_output_tokens=8,
            planned_reasoning_tokens=2,
            planned_completion_tokens=10,
            request_token_plan_sha256="2" * 64,
            request_limit_scope=_issue_trusted_request_limit_scope(slots[0].logical_request_id),
        )
    assert adopted.persistent is not None
    assert adopted.persistent.request_id == slots[0].request_id
    await reopened.release(adopted)

    wrong = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
        global_input_token_budget=20,
        global_output_token_budget=40,
        per_model_usd_caps={"alpha/atlas-secure": "1"},
        per_role_usd_caps={"review": "1"},
    )
    changed_slots = (replace(slots[0], maximum_cost_usd=Decimal("0.21")), slots[1])
    with pytest.raises(BudgetReservationStateError, match="durable initial slots"):
        await wrong.recover_portfolio("1" * 64, changed_slots)
    assert wrong.reserved_usd == 0
    await reopened.release_portfolio(recovered)
    assert reopened.reserved_usd == 0


@pytest.mark.asyncio
async def test_portfolio_recovery_restores_a_released_retry_prefix(tmp_path) -> None:
    request_material = "abc"
    bound = _endpoint_bound(request_material)
    manager, ledger = _portfolio_manager(tmp_path)
    slots = (
        _portfolio_slot(bound),
        _portfolio_slot(bound, attempt_ordinal=2),
    )
    portfolio = await manager.reserve_portfolio("2" * 64, slots)
    async with manager.portfolio_task_scope(portfolio, slots[0].task_id):
        first = await manager.reserve(
            slots[0].request_id,
            slots[0].role,
            request_material,
            endpoint_cost_bound=bound,
            exact_model_id=slots[0].exact_model_id,
            planned_prompt_tokens=3,
            planned_visible_output_tokens=8,
            planned_reasoning_tokens=2,
            planned_completion_tokens=10,
            request_token_plan_sha256="3" * 64,
            request_limit_scope=_issue_trusted_request_limit_scope(slots[0].logical_request_id),
        )
        await manager.release(first)

    reopened = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=2,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
        global_input_token_budget=20,
        global_output_token_budget=40,
        per_model_usd_caps={"alpha/atlas-secure": "1"},
        per_role_usd_caps={"review": "1"},
    )
    recovered = await reopened.recover_portfolio("2" * 64, slots)
    recovery_scope = _issue_trusted_budget_recovery_scope(())
    await reopened.restore_recovered_usage((), recovery_scope=recovery_scope)

    async with reopened.portfolio_task_scope(recovered, slots[1].task_id) as next_slot:
        assert next_slot == slots[1]
        second = await reopened.reserve(
            slots[1].request_id,
            slots[1].role,
            request_material,
            endpoint_cost_bound=bound,
            exact_model_id=slots[1].exact_model_id,
            planned_prompt_tokens=3,
            planned_visible_output_tokens=8,
            planned_reasoning_tokens=2,
            planned_completion_tokens=10,
            request_token_plan_sha256="4" * 64,
            request_limit_scope=_issue_trusted_request_limit_scope(slots[1].logical_request_id),
        )
    await reopened.release(second)
    await reopened.release_portfolio(recovered)
    assert reopened.reserved_usd == 0


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


def test_endpoint_pricing_preserves_exact_decimal_under_hostile_ambient_context() -> None:
    exact = "0.000002000000000000000000000000000001"

    with localcontext() as context:
        context.prec = 6
        bound = EndpointRequestCostBound.from_endpoint_pricing(
            exact_model_id="alpha/atlas-secure",
            provider_endpoint="approved-provider",
            request_material="request",
            pricing={"completion": exact, "prompt": "0.000001"},
            maximum_units={"completion": 1, "prompt": 1},
        )

    completion = next(
        component for component in bound.components if component.pricing_field == "completion"
    )
    assert completion.unit_price_usd == Decimal(exact)


@pytest.mark.asyncio
async def test_two_decimal_reconciliations_retain_canonical_float_projection(tmp_path) -> None:
    request_material = "request"
    bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id="alpha/atlas-secure",
        provider_endpoint="approved-provider",
        request_material=request_material,
        pricing={"completion": "0", "prompt": "0", "request": "0.3"},
        maximum_units={"completion": 10, "prompt": len(request_material), "request": 1},
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "two-reconciliations.json",
        cap_usd=Decimal("0.7"),
    )
    manager = BudgetManager(
        total_usd=0.7,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=3,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )

    first = await manager.reserve(
        "request-a",
        "review",
        request_material,
        endpoint_cost_bound=bound,
    )
    await manager.reconcile(first, Decimal("0.1"))
    second = await manager.reserve(
        "request-b",
        "review",
        request_material,
        endpoint_cost_bound=bound,
    )
    await manager.reconcile(second, Decimal("0.2"))

    assert manager.spent_usd_exact == Decimal("0.3")
    assert manager.spent_usd == float(Decimal("0.3"))
    assert ledger.snapshot().spent_usd == Decimal("0.3")


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


def _scoped_manager(
    *,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    model_caps: dict[str, str] | None = None,
    role_caps: dict[str, str] | None = None,
    max_requests: int = 10,
) -> BudgetManager:
    return BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=max_requests,
        global_input_token_budget=input_tokens,
        global_output_token_budget=output_tokens,
        per_model_usd_caps=model_caps,
        per_role_usd_caps=role_caps,
    )


@pytest.mark.asyncio
async def test_scheduler_request_scopes_bound_each_task_without_splitting_role_accounting() -> None:
    manager = _scoped_manager(
        input_tokens=20,
        output_tokens=20,
        role_caps={"review": "0.001"},
        max_requests=1,
    )
    first_scope = _issue_trusted_request_limit_scope("campaign-1.task-a")
    second_scope = _issue_trusted_request_limit_scope("campaign-1.task-b")

    reservations = await asyncio.gather(
        manager.reserve(
            "request-a",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=4,
            planned_visible_output_tokens=3,
            planned_reasoning_tokens=1,
            planned_completion_tokens=4,
            request_token_plan_sha256="a" * 64,
            request_limit_scope=first_scope,
        ),
        manager.reserve(
            "request-b",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=4,
            planned_visible_output_tokens=3,
            planned_reasoning_tokens=1,
            planned_completion_tokens=4,
            request_token_plan_sha256="b" * 64,
            request_limit_scope=second_scope,
        ),
    )

    assert [reservation.role for reservation in reservations] == ["review", "review"]
    assert manager.reserved_role_usd("review") == Decimal("0.000022")
    assert manager.reserved_input_tokens == manager.reserved_output_tokens == 8
    for reservation, scope in zip(
        reservations,
        (first_scope.identifier, second_scope.identifier),
        strict=True,
    ):
        evidence = reservation.request_limit_reservation_evidence
        assert evidence is not None
        assert reservation.request_limit_scope == evidence.request_limit_scope == scope
        assert evidence.request_limit_count_before == 0
        assert evidence.request_limit_count_after == evidence.request_limit_maximum == 1


@pytest.mark.asyncio
async def test_concurrent_scheduler_retries_cannot_cross_one_task_request_limit() -> None:
    manager = _scoped_manager(max_requests=1)
    scope = _issue_trusted_request_limit_scope("campaign-1.same-task")

    results = await asyncio.gather(
        manager.reserve(
            "request-a",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_visible_output_tokens=1,
            planned_reasoning_tokens=0,
            planned_completion_tokens=1,
            request_token_plan_sha256="a" * 64,
            request_limit_scope=scope,
        ),
        manager.reserve(
            "request-b",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_visible_output_tokens=1,
            planned_reasoning_tokens=0,
            planned_completion_tokens=1,
            request_token_plan_sha256="b" * 64,
            request_limit_scope=scope,
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(result, Reservation) for result in results) == 1
    assert sum(isinstance(result, BudgetExhaustedError) for result in results) == 1


@pytest.mark.asyncio
async def test_scheduler_scope_never_bypasses_aggregate_role_or_token_caps() -> None:
    manager = _scoped_manager(
        input_tokens=6,
        output_tokens=6,
        role_caps={"review": "0.000015"},
        max_requests=1,
    )

    results = await asyncio.gather(
        *(
            manager.reserve(
                f"request-{index}",
                "review",
                "x",
                exact_model_id="alpha/atlas-secure",
                planned_prompt_tokens=6,
                planned_visible_output_tokens=6,
                planned_reasoning_tokens=0,
                planned_completion_tokens=6,
                request_token_plan_sha256=f"{index}" * 64,
                request_limit_scope=_issue_trusted_request_limit_scope(f"campaign-1.task-{index}"),
            )
            for index in (1, 2)
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(result, Reservation) for result in results) == 1
    assert sum(isinstance(result, BudgetExhaustedError) for result in results) == 1
    assert manager.reserved_input_tokens == manager.reserved_output_tokens == 6
    assert manager.reserved_role_usd("review") == Decimal("0.000011")


@pytest.mark.asyncio
async def test_unscheduled_request_limit_remains_aggregated_by_semantic_role() -> None:
    manager = _scoped_manager(max_requests=1)
    await manager.reserve("request-a", "review", "x")

    with pytest.raises(BudgetExhaustedError, match="request limit reached for role review"):
        await manager.reserve("request-b", "review", "x")


@pytest.mark.asyncio
async def test_request_limit_scope_requires_trusted_plan_bound_identity() -> None:
    manager = _scoped_manager(max_requests=1)
    with pytest.raises(BudgetReservationStateError, match="capability is invalid"):
        await manager.reserve(
            "request-a",
            "review",
            "x",
            request_limit_scope="campaign-1.task-a",  # type: ignore[arg-type]
        )
    with pytest.raises(BudgetReservationStateError, match="plan-bound"):
        await manager.reserve(
            "request-b",
            "review",
            "x",
            request_limit_scope=_issue_trusted_request_limit_scope("campaign-1.task-b"),
        )
    with pytest.raises(BudgetReservationStateError, match="restricted non-secret"):
        _issue_trusted_request_limit_scope("private/task/path")


@pytest.mark.asyncio
async def test_scoped_concurrent_reservations_are_all_or_nothing() -> None:
    manager = _scoped_manager(
        input_tokens=10,
        output_tokens=10,
        model_caps={"alpha/atlas-secure": "0.000015"},
        role_caps={"review": "0.000015"},
    )

    results = await asyncio.gather(
        manager.reserve(
            "request-a",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=6,
            planned_completion_tokens=6,
        ),
        manager.reserve(
            "request-b",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=6,
            planned_completion_tokens=6,
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(result, Reservation) for result in results) == 1
    assert sum(isinstance(result, BudgetExhaustedError) for result in results) == 1
    assert manager.reserved_usd == pytest.approx(0.000011)
    assert manager.reserved_input_tokens == 6
    assert manager.reserved_output_tokens == 6
    assert manager.reserved_model_usd("alpha/atlas-secure") == Decimal("0.000011")
    assert manager.reserved_role_usd("review") == Decimal("0.000011")


@pytest.mark.asyncio
async def test_per_model_usd_cap_blocks_only_the_exhausted_model() -> None:
    manager = _scoped_manager(
        model_caps={
            "alpha/atlas-secure": "0.000015",
            "beta/beacon-secure": "0.000015",
        }
    )
    await manager.reserve(
        "request-a",
        "review-a",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=1,
        planned_completion_tokens=10,
    )

    with pytest.raises(BudgetExhaustedError, match="model USD budget"):
        await manager.reserve(
            "request-b",
            "review-b",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_completion_tokens=10,
        )
    other = await manager.reserve(
        "request-c",
        "review-c",
        "x",
        exact_model_id="beta/beacon-secure",
        planned_prompt_tokens=1,
        planned_completion_tokens=10,
    )

    assert other.exact_model_id == "beta/beacon-secure"


@pytest.mark.asyncio
async def test_configured_scoped_caps_reject_unlisted_models_and_roles() -> None:
    model_scoped = _scoped_manager(model_caps={"alpha/atlas-secure": "1"})
    with pytest.raises(BudgetExhaustedError, match="no configured model USD budget"):
        await model_scoped.reserve(
            "request-model",
            "review",
            "x",
            exact_model_id="beta/beacon-secure",
            planned_prompt_tokens=1,
            planned_completion_tokens=1,
        )

    role_scoped = _scoped_manager(role_caps={"review": "1"})
    with pytest.raises(BudgetExhaustedError, match="no configured role USD budget"):
        await role_scoped.reserve(
            "request-role",
            "unlisted",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_completion_tokens=1,
        )


@pytest.mark.asyncio
async def test_per_role_usd_cap_blocks_only_the_exhausted_role() -> None:
    manager = _scoped_manager(
        role_caps={
            "review-a": "0.000015",
            "review-b": "0.000015",
        }
    )
    await manager.reserve(
        "request-a",
        "review-a",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=1,
        planned_completion_tokens=10,
    )

    with pytest.raises(BudgetExhaustedError, match="role USD budget"):
        await manager.reserve(
            "request-b",
            "review-a",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_completion_tokens=10,
        )
    other = await manager.reserve(
        "request-c",
        "review-b",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=1,
        planned_completion_tokens=10,
    )

    assert other.role == "review-b"


@pytest.mark.asyncio
async def test_release_restores_every_scoped_reservation() -> None:
    manager = _scoped_manager(
        input_tokens=5,
        output_tokens=5,
        model_caps={"alpha/atlas-secure": "0.000011"},
        role_caps={"review": "0.000011"},
    )
    first = await manager.reserve(
        "request-a",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=5,
        planned_completion_tokens=5,
    )

    await manager.release(first)
    await manager.release(first)

    assert manager.reserved_usd == 0
    assert manager.reserved_input_tokens == 0
    assert manager.reserved_output_tokens == 0
    assert manager.reserved_model_usd("alpha/atlas-secure") == 0
    assert manager.reserved_role_usd("review") == 0
    second = await manager.reserve(
        "request-b",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=5,
        planned_completion_tokens=5,
    )
    assert second.identifier == "request-b"


@pytest.mark.asyncio
async def test_reconcile_replaces_scoped_reservations_with_actual_usage() -> None:
    manager = _scoped_manager(
        input_tokens=20,
        output_tokens=10,
        model_caps={"alpha/atlas-secure": "0.001"},
        role_caps={"review": "0.001"},
    )
    reservation = await manager.reserve(
        "request-a",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=10,
        planned_completion_tokens=5,
    )

    accounted = await manager.reconcile(
        reservation,
        Decimal("0.000005"),
        actual_prompt_tokens=7,
        actual_completion_tokens=3,
    )

    assert accounted == 0.000005
    assert manager.reserved_input_tokens == 0
    assert manager.reserved_output_tokens == 0
    assert manager.spent_input_tokens == 7
    assert manager.spent_output_tokens == 3
    assert manager.spent_model_usd("alpha/atlas-secure") == Decimal("0.000005")
    assert manager.spent_role_usd("review") == Decimal("0.000005")


@pytest.mark.asyncio
async def test_unknown_actual_usage_conservatively_charges_reservation() -> None:
    manager = _scoped_manager(input_tokens=20, output_tokens=10)
    reservation = await manager.reserve(
        "request-a",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=9,
        planned_completion_tokens=4,
    )

    accounted = await manager.reconcile(reservation, None)

    assert accounted == pytest.approx(0.000011)
    assert manager.spent_input_tokens == 9
    assert manager.spent_output_tokens == 4
    assert manager.spent_model_usd("alpha/atlas-secure") == Decimal("0.000011")


@pytest.mark.asyncio
async def test_token_overrun_is_terminal_and_does_not_double_count() -> None:
    manager = _scoped_manager(input_tokens=5, output_tokens=2)
    reservation = await manager.reserve(
        "request-a",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=5,
        planned_completion_tokens=2,
    )

    with pytest.raises(TokenReservationOverrunError):
        await manager.reconcile(
            reservation,
            Decimal("0.000005"),
            actual_prompt_tokens=6,
            actual_completion_tokens=3,
        )
    with pytest.raises(TokenReservationOverrunError):
        await manager.reconcile(
            reservation,
            Decimal("0.000005"),
            actual_prompt_tokens=6,
            actual_completion_tokens=3,
        )

    assert manager.spent_input_tokens == 6
    assert manager.spent_output_tokens == 3
    assert manager.spent_usd == 0.000005
    assert manager.reserved_input_tokens == 0
    assert manager.reserved_output_tokens == 0


@pytest.mark.asyncio
async def test_scoped_cost_overrun_is_terminal_and_does_not_double_count() -> None:
    manager = _scoped_manager(model_caps={"alpha/atlas-secure": "0.001"})
    reservation = await manager.reserve(
        "request-a",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=1,
        planned_completion_tokens=10,
    )

    with pytest.raises(CostReservationOverrunError):
        await manager.reconcile(
            reservation,
            Decimal("0.00002"),
            actual_prompt_tokens=1,
            actual_completion_tokens=10,
        )
    with pytest.raises(CostReservationOverrunError):
        await manager.reconcile(
            reservation,
            Decimal("0.00002"),
            actual_prompt_tokens=1,
            actual_completion_tokens=10,
        )

    assert manager.spent_usd == 0.00002
    assert manager.spent_model_usd("alpha/atlas-secure") == Decimal("0.00002")
    assert manager.reserved_model_usd("alpha/atlas-secure") == 0


@pytest.mark.asyncio
async def test_legacy_reservation_api_remains_valid_without_scoped_budgets() -> None:
    manager = _scoped_manager()

    reservation = await manager.reserve("request-a", "review", "legacy prompt")
    accounted = await manager.reconcile(reservation, None)

    assert reservation.exact_model_id is None
    assert reservation.planned_prompt_tokens is None
    assert reservation.planned_completion_tokens is None
    assert accounted == reservation.estimated_cost_usd
    assert manager.spent_input_tokens == 0
    assert manager.spent_output_tokens == 0


@pytest.mark.asyncio
async def test_scoped_counters_are_process_local_while_global_ledger_is_durable(
    tmp_path,
) -> None:
    ledger = AtomicCostLedger.initialize(
        tmp_path / "model-cost-ledger.json",
        cap_usd=Decimal("1"),
    )
    manager = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        per_model_usd_caps={"alpha/atlas-secure": "1"},
    )
    reservation = await manager.reserve(
        "request-a",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=1,
        planned_completion_tokens=10,
    )
    await manager.reconcile(
        reservation,
        Decimal("0.000005"),
        actual_prompt_tokens=1,
        actual_completion_tokens=2,
    )

    reopened = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        per_model_usd_caps={"alpha/atlas-secure": "1"},
    )

    assert reopened.spent_usd == 0.000005
    assert reopened.spent_model_usd("alpha/atlas-secure") == 0
    assert reopened.spent_input_tokens == 0
    assert reopened.spent_output_tokens == 0


def test_scoped_budget_configuration_rejects_ambiguous_keys_and_caps() -> None:
    with pytest.raises(ValueError, match="model budget key"):
        _scoped_manager(model_caps={"not-an-exact-model": "1"})
    with pytest.raises(ValueError, match="role budget key"):
        _scoped_manager(role_caps={"invalid role": "1"})
    with pytest.raises(ValueError, match="Decimal-safe"):
        BudgetManager(
            total_usd=1,
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=10,
            per_model_usd_caps={"alpha/atlas-secure": 0.1},  # type: ignore[dict-item]
        )
    with pytest.raises(ValueError, match="finite"):
        _scoped_manager(role_caps={"review": "NaN"})


@pytest.mark.asyncio
async def test_scoped_reservation_requires_a_complete_exact_token_plan() -> None:
    manager = _scoped_manager(input_tokens=10)

    with pytest.raises(BudgetReservationStateError, match="supplied together"):
        await manager.reserve(
            "request-a",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
        )
    with pytest.raises(BudgetReservationStateError, match="exact model"):
        await manager.reserve(
            "request-b",
            "review",
            "x",
            planned_prompt_tokens=1,
            planned_completion_tokens=1,
        )
    with pytest.raises(ValueError, match="model budget key"):
        await manager.reserve(
            "request-c",
            "review",
            "x",
            exact_model_id="not-exact",
            planned_prompt_tokens=1,
            planned_completion_tokens=1,
        )

    assert manager.reserved_usd == 0
    assert manager.reserved_input_tokens == 0


@pytest.mark.asyncio
async def test_plan_bound_reservation_carries_self_hashed_atomic_token_evidence() -> None:
    manager = _scoped_manager(input_tokens=20, output_tokens=10)
    canary_prompt = "PRIVATE_PROMPT_CANARY"
    prior = await manager.reserve(
        "request-prior",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=2,
        planned_completion_tokens=1,
    )
    await manager.reconcile(
        prior,
        Decimal("0.000001"),
        actual_prompt_tokens=2,
        actual_completion_tokens=1,
    )

    reservation = await manager.reserve(
        "request-plan-a",
        "review",
        canary_prompt,
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=7,
        planned_visible_output_tokens=2,
        planned_reasoning_tokens=1,
        planned_completion_tokens=3,
        request_token_plan_sha256="a" * 64,
    )

    evidence = reservation.token_reservation_evidence
    assert evidence is not None
    assert evidence.request_id == reservation.identifier
    assert evidence.exact_model_id == "alpha/atlas-secure"
    assert evidence.role == "review"
    assert evidence.request_token_plan_sha256 == "a" * 64
    assert evidence.schema_version == "2.0"
    assert evidence.planned_visible_output_tokens == 2
    assert evidence.planned_reasoning_tokens == 1
    assert evidence.planned_completion_tokens == 3
    assert evidence.global_input_token_limit == 20
    assert evidence.global_output_token_limit == 10
    assert evidence.before.spent_input_tokens == 2
    assert evidence.before.reserved_input_tokens == 0
    assert evidence.before.remaining_input_tokens == 18
    assert evidence.after.spent_input_tokens == 2
    assert evidence.after.reserved_input_tokens == 7
    assert evidence.after.remaining_input_tokens == 11
    assert evidence.before.spent_output_tokens == 1
    assert evidence.before.reserved_output_tokens == 0
    assert evidence.before.remaining_output_tokens == 9
    assert evidence.after.spent_output_tokens == 1
    assert evidence.after.reserved_output_tokens == 3
    assert evidence.after.remaining_output_tokens == 6
    serialized = json.dumps(evidence.model_dump(mode="json"), sort_keys=True)
    assert canary_prompt not in serialized
    assert (
        AtomicTokenReservationEvidence.model_validate(evidence.model_dump(mode="json")) == evidence
    )


@pytest.mark.asyncio
async def test_plan_hash_requires_complete_exact_token_reservation_fields() -> None:
    manager = _scoped_manager()

    with pytest.raises(BudgetReservationStateError, match="exact model and complete"):
        await manager.reserve(
            "request-no-model",
            "review",
            "x",
            planned_prompt_tokens=1,
            planned_completion_tokens=1,
            request_token_plan_sha256="a" * 64,
        )
    with pytest.raises(BudgetReservationStateError, match="exact model and complete"):
        await manager.reserve(
            "request-no-counts",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            request_token_plan_sha256="a" * 64,
        )
    with pytest.raises(BudgetReservationStateError, match="plan hash is invalid"):
        await manager.reserve(
            "request-invalid-hash",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_completion_tokens=1,
            request_token_plan_sha256="not-a-hash",
        )
    with pytest.raises(
        BudgetReservationStateError,
        match="requires visible-output and reasoning",
    ):
        await manager.reserve(
            "request-no-split",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_completion_tokens=1,
            request_token_plan_sha256="a" * 64,
        )
    with pytest.raises(BudgetReservationStateError, match="supplied together"):
        await manager.reserve(
            "request-partial-split",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_visible_output_tokens=1,
            planned_completion_tokens=1,
            request_token_plan_sha256="a" * 64,
        )
    with pytest.raises(BudgetReservationStateError, match="do not conserve"):
        await manager.reserve(
            "request-invalid-split",
            "review",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=1,
            planned_visible_output_tokens=1,
            planned_reasoning_tokens=1,
            planned_completion_tokens=3,
            request_token_plan_sha256="a" * 64,
        )

    assert manager.reserved_usd == 0
    assert manager.reserved_input_tokens == 0
    assert manager.reserved_output_tokens == 0


@pytest.mark.asyncio
async def test_atomic_token_evidence_rejects_tampering_and_resealed_nonconservation() -> None:
    manager = _scoped_manager(input_tokens=20, output_tokens=10)
    reservation = await manager.reserve(
        "request-plan-a",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=7,
        planned_visible_output_tokens=2,
        planned_reasoning_tokens=1,
        planned_completion_tokens=3,
        request_token_plan_sha256="a" * 64,
    )
    evidence = reservation.token_reservation_evidence
    assert evidence is not None
    serialized = evidence.model_dump(mode="json")

    changed_role = dict(serialized)
    changed_role["role"] = "falsifier"
    with pytest.raises(ValidationError, match="self-hash"):
        AtomicTokenReservationEvidence.model_validate(changed_role)

    changed_conservation = json.loads(json.dumps(serialized))
    changed_conservation["after"]["reserved_input_tokens"] = 8
    changed_conservation["after"]["remaining_input_tokens"] = 12
    hash_payload = dict(changed_conservation)
    hash_payload.pop("evidence_sha256")
    changed_conservation["evidence_sha256"] = hashlib.sha256(
        json.dumps(
            hash_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(ValidationError, match="does not conserve"):
        AtomicTokenReservationEvidence.model_validate(changed_conservation)

    changed_split = json.loads(json.dumps(serialized))
    changed_split["planned_reasoning_tokens"] = 2
    split_hash_payload = dict(changed_split)
    split_hash_payload.pop("evidence_sha256")
    changed_split["evidence_sha256"] = hashlib.sha256(
        json.dumps(
            split_hash_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(ValidationError, match="reasoning reservations do not conserve"):
        AtomicTokenReservationEvidence.model_validate(changed_split)

    with pytest.raises(ValueError, match="differ from its atomic token evidence"):
        replace(reservation, planned_prompt_tokens=8)
    with pytest.raises(ValueError, match="do not conserve"):
        replace(reservation, planned_reasoning_tokens=2)


@pytest.mark.asyncio
async def test_concurrent_plan_bound_reservations_have_distinct_atomic_snapshots() -> None:
    manager = _scoped_manager(input_tokens=20, output_tokens=20)

    results = await asyncio.gather(
        manager.reserve(
            "request-plan-a",
            "review-a",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=6,
            planned_visible_output_tokens=3,
            planned_reasoning_tokens=1,
            planned_completion_tokens=4,
            request_token_plan_sha256="a" * 64,
        ),
        manager.reserve(
            "request-plan-b",
            "review-b",
            "x",
            exact_model_id="alpha/atlas-secure",
            planned_prompt_tokens=6,
            planned_visible_output_tokens=3,
            planned_reasoning_tokens=1,
            planned_completion_tokens=4,
            request_token_plan_sha256="b" * 64,
        ),
    )

    evidence = [reservation.token_reservation_evidence for reservation in results]
    assert all(item is not None for item in evidence)
    ordered = sorted(
        (item for item in evidence if item is not None),
        key=lambda item: item.before.reserved_input_tokens,
    )
    assert [
        (
            item.before.reserved_input_tokens,
            item.after.reserved_input_tokens,
            item.before.reserved_output_tokens,
            item.after.reserved_output_tokens,
        )
        for item in ordered
    ] == [(0, 6, 0, 4), (6, 12, 4, 8)]
    assert ordered[0].after == ordered[1].before
    assert ordered[0].evidence_sha256 != ordered[1].evidence_sha256
    assert manager.reserved_input_tokens == 12
    assert manager.reserved_output_tokens == 8
    assert manager.remaining_input_tokens == 8
    assert manager.remaining_output_tokens == 12


@pytest.mark.asyncio
async def test_split_token_reconciliation_accepts_only_each_reserved_output_slice() -> None:
    manager = _scoped_manager(input_tokens=20, output_tokens=10)
    reservation = await manager.reserve(
        "request-plan",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=8,
        planned_visible_output_tokens=3,
        planned_reasoning_tokens=2,
        planned_completion_tokens=5,
        request_token_plan_sha256="a" * 64,
    )

    accounted = await manager.reconcile(
        reservation,
        Decimal("0.000005"),
        actual_prompt_tokens=7,
        actual_completion_tokens=4,
        actual_reasoning_tokens=1,
    )

    assert accounted == 0.000005
    assert manager.spent_input_tokens == 7
    assert manager.spent_output_tokens == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("visible_reserve", "reasoning_reserve", "actual_completion", "actual_reasoning"),
    (
        (3, 1, 4, 2),
        (2, 2, 4, 1),
        (3, 1, 2, None),
    ),
)
async def test_split_token_reconciliation_fails_closed_on_unproven_or_exceeded_slice(
    visible_reserve: int,
    reasoning_reserve: int,
    actual_completion: int,
    actual_reasoning: int | None,
) -> None:
    manager = _scoped_manager(input_tokens=20, output_tokens=10)
    reservation = await manager.reserve(
        "request-plan",
        "review",
        "x",
        exact_model_id="alpha/atlas-secure",
        planned_prompt_tokens=8,
        planned_visible_output_tokens=visible_reserve,
        planned_reasoning_tokens=reasoning_reserve,
        planned_completion_tokens=visible_reserve + reasoning_reserve,
        request_token_plan_sha256="a" * 64,
    )

    with pytest.raises(TokenReservationOverrunError, match="did not prove"):
        await manager.reconcile(
            reservation,
            Decimal("0.000005"),
            actual_prompt_tokens=7,
            actual_completion_tokens=actual_completion,
            actual_reasoning_tokens=actual_reasoning,
        )
    with pytest.raises(TokenReservationOverrunError, match="did not prove"):
        await manager.reconcile(
            reservation,
            Decimal("0.000005"),
            actual_prompt_tokens=7,
            actual_completion_tokens=actual_completion,
            actual_reasoning_tokens=actual_reasoning,
        )

    assert manager.spent_usd == 0.000005
    assert manager.spent_input_tokens == 7
    assert manager.spent_output_tokens == actual_completion
    assert manager.reserved_input_tokens == 0
    assert manager.reserved_output_tokens == 0


@pytest.mark.asyncio
async def test_budget_recovery_aggregates_parent_and_children_under_one_root_scope(
    tmp_path,
) -> None:
    root_scope = "family-root-request"
    records = tuple(
        sorted(
            (
                _shared_recovery_usage(
                    root_scope,
                    root_scope=root_scope,
                    count_before=0,
                    cost_usd_exact="0.01",
                ),
                _shared_recovery_usage(
                    "family-root-request.child-a",
                    root_scope=root_scope,
                    count_before=1,
                    cost_usd_exact="0.02",
                ),
                _shared_recovery_usage(
                    "family-root-request.child-b",
                    root_scope=root_scope,
                    count_before=2,
                    cost_usd_exact="0.03",
                ),
            ),
            key=lambda item: item.request_id,
        )
    )
    manager, ledger = _recovery_manager(tmp_path, records)
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        shared_request_limit_scope=root_scope,
        shared_request_limit_count_before=0,
    )

    await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert not manager.recovery_required
    assert manager.spent_usd_exact == Decimal("0.06")
    assert ledger.snapshot().spent_usd == Decimal("0.06")
    next_request = await manager.reserve(
        "family-root-request.child-c",
        "source_audit",
        "x",
        exact_model_id="author/exact-model",
        planned_prompt_tokens=1,
        planned_visible_output_tokens=1,
        planned_reasoning_tokens=0,
        planned_completion_tokens=1,
        request_token_plan_sha256="a" * 64,
        request_limit_scope=_issue_trusted_request_limit_scope(root_scope),
    )
    evidence = next_request.request_limit_reservation_evidence
    assert evidence is not None
    assert evidence.request_limit_scope == root_scope
    assert evidence.request_limit_count_before == 3
    assert evidence.request_limit_count_after == 4
    await manager.release(next_request)


@pytest.mark.asyncio
async def test_budget_recovery_interleaves_typed_release_bridge_and_later_usage(
    tmp_path,
) -> None:
    root_scope = "family-root-request"
    release_request_id = f"{root_scope}.child-release"
    records = tuple(
        sorted(
            (
                _shared_recovery_usage(
                    root_scope,
                    root_scope=root_scope,
                    count_before=0,
                ),
                _shared_recovery_usage(
                    f"{root_scope}.child-later",
                    root_scope=root_scope,
                    count_before=2,
                ),
            ),
            key=lambda item: item.request_id,
        )
    )
    manager, ledger = _recovery_manager(tmp_path, records)
    released = ledger.reserve(release_request_id, Decimal("0.10"))
    ledger.release(released, reason=ReleaseReason.FAILED_BEFORE_SEND)
    recovered_attempt = _recovered_no_usage_attempt(
        release_request_id,
        logical_request_id=release_request_id,
        request_limit_scope=root_scope,
        count_before=1,
        count_after=2,
        maximum=10,
    )
    before = ledger.snapshot()

    for recovered_manager in (manager, _budget_manager_for_recovery_ledger(ledger)):
        recovery_scope = _issue_trusted_budget_recovery_scope(
            records,
            non_usage_attempts=(recovered_attempt,),
            shared_request_limit_roots=((root_scope, 0),),
        )
        await recovered_manager.restore_recovered_usage(
            records,
            recovery_scope=recovery_scope,
        )
        assert recovered_manager.spent_usd_exact == Decimal("0.02")
        assert ledger.snapshot() == before

    next_request = await recovered_manager.reserve(
        f"{root_scope}.child-next",
        "source_audit",
        "x",
        exact_model_id="author/exact-model",
        planned_prompt_tokens=1,
        planned_visible_output_tokens=1,
        planned_reasoning_tokens=0,
        planned_completion_tokens=1,
        request_token_plan_sha256="a" * 64,
        request_limit_scope=_issue_trusted_request_limit_scope(root_scope),
    )
    assert next_request.request_limit_reservation_evidence is not None
    assert next_request.request_limit_reservation_evidence.request_limit_count_before == 3
    await recovered_manager.release(next_request)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ("gap", "overlap", "orphan-root", "wrong-maximum", "adopted-before-usage"),
)
async def test_budget_recovery_rejects_invalid_no_usage_shared_bridge(
    tmp_path,
    case: str,
) -> None:
    root_scope = "family-root-request"
    later_count = 2
    attempt_scope = root_scope
    count_before = 1
    count_after = 2
    maximum = 10
    status = "released_proven_pre_send"
    if case == "gap":
        later_count = 3
        count_before = 2
        count_after = 3
    elif case == "overlap":
        count_before = 0
        count_after = 1
    elif case == "orphan-root":
        attempt_scope = "orphan-root-request"
    elif case == "wrong-maximum":
        maximum = 9
    elif case == "adopted-before-usage":
        status = "adopted_proven_pre_send"
    records = tuple(
        sorted(
            (
                _shared_recovery_usage(
                    root_scope,
                    root_scope=root_scope,
                    count_before=0,
                ),
                _shared_recovery_usage(
                    f"{root_scope}.child-later",
                    root_scope=root_scope,
                    count_before=later_count,
                ),
            ),
            key=lambda item: item.request_id,
        )
    )
    manager, ledger = _recovery_manager(tmp_path, records)
    request_id = f"{root_scope}.child-bridge"
    persistent = ledger.reserve(request_id, Decimal("0.10"))
    if status == "released_proven_pre_send":
        ledger.release(persistent, reason=ReleaseReason.FAILED_BEFORE_SEND)
    recovered_attempt = _recovered_no_usage_attempt(
        request_id,
        logical_request_id=request_id,
        status=status,
        request_limit_scope=attempt_scope,
        count_before=count_before,
        count_after=count_after,
        maximum=maximum,
    )
    before = ledger.snapshot()
    spent_before = manager.spent_usd_exact
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        non_usage_attempts=(recovered_attempt,),
        shared_request_limit_roots=((root_scope, 0),),
    )

    with pytest.raises(BudgetReservationStateError, match="shared recover"):
        await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert manager.recovery_required
    assert manager.spent_usd_exact == spent_before
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_budget_recovery_rejects_no_usage_id_colliding_with_atomic_attempt(
    tmp_path,
) -> None:
    record = _retry_token_bound_creditable_record()
    collision_id = f"{record.request_id}:attempt:2"
    ledger = AtomicCostLedger.initialize(
        tmp_path / "atomic-attempt-collision-ledger.json",
        cap_usd=Decimal("1"),
    )
    first = ledger.reserve(record.request_id, Decimal("0.10"))
    ledger.reconcile(first, Decimal(record.reported_cost_usd_exact or "0"))
    collision = ledger.reserve(collision_id, Decimal("0.10"))
    ledger.release(collision, reason=ReleaseReason.FAILED_BEFORE_SEND)
    manager = _budget_manager_for_recovery_ledger(ledger)
    recovered_attempt = _recovered_no_usage_attempt(
        collision_id,
        logical_request_id=record.request_id,
        request_limit_scope=record.request_id,
        count_before=1,
        count_after=2,
        maximum=10,
    )
    before = ledger.snapshot()
    recovery_scope = _issue_trusted_budget_recovery_scope(
        (record,),
        non_usage_attempts=(recovered_attempt,),
        shared_request_limit_roots=((record.request_id, 0),),
    )

    with pytest.raises(BudgetReservationStateError, match="repeat usage custody"):
        await manager.restore_recovered_usage((record,), recovery_scope=recovery_scope)

    assert manager.recovery_required
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_budget_recovery_rejects_nonshared_attempt_ordinal_above_limit(
    tmp_path,
) -> None:
    logical_request_id = "ordinary-release-request"
    ledger = AtomicCostLedger.initialize(
        tmp_path / "over-limit-no-usage-ledger.json",
        cap_usd=Decimal("1"),
    )
    attempts = []
    for ordinal in range(1, 12):
        request_id = (
            logical_request_id if ordinal == 1 else f"{logical_request_id}:attempt:{ordinal}"
        )
        reservation = ledger.reserve(request_id, Decimal("0.01"))
        ledger.release(reservation, reason=ReleaseReason.FAILED_BEFORE_SEND)
        attempts.append(
            _recovered_no_usage_attempt(
                request_id,
                logical_request_id=logical_request_id,
                request_limit_scope=None,
                count_before=None,
                count_after=None,
                maximum=None,
                reserved_cost_usd_exact=Decimal("0.01"),
            )
        )
    manager = _budget_manager_for_recovery_ledger(ledger)
    before = ledger.snapshot()
    recovery_scope = _issue_trusted_budget_recovery_scope(
        (),
        non_usage_attempts=tuple(attempts),
    )

    with pytest.raises(BudgetReservationStateError, match="ordinals are not contiguous"):
        await manager.restore_recovered_usage((), recovery_scope=recovery_scope)

    assert manager.recovery_required
    assert manager.spent_usd_exact == 0
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_budget_recovery_restores_two_disjoint_root_chains(tmp_path) -> None:
    roots = ("family-a-request", "family-b-request")
    records = tuple(
        sorted(
            (
                *(
                    _shared_recovery_usage(
                        root,
                        root_scope=root,
                        count_before=0,
                    )
                    for root in roots
                ),
                *(
                    _shared_recovery_usage(
                        f"{root}.child-{ordinal}",
                        root_scope=root,
                        count_before=ordinal,
                    )
                    for root in roots
                    for ordinal in (1, 2)
                ),
            ),
            key=lambda item: item.request_id,
        )
    )
    manager, ledger = _recovery_manager(tmp_path, records)
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        shared_request_limit_roots=tuple((root, 0) for root in roots),
    )

    await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert not manager.recovery_required
    assert manager.spent_usd_exact == Decimal("0.06")
    assert ledger.snapshot().spent_usd == Decimal("0.06")
    next_reservations = tuple(
        [
            await manager.reserve(
                f"{root}.child-3",
                "source_audit",
                "x",
                exact_model_id="author/exact-model",
                planned_prompt_tokens=1,
                planned_visible_output_tokens=1,
                planned_reasoning_tokens=0,
                planned_completion_tokens=1,
                request_token_plan_sha256="a" * 64,
                request_limit_scope=_issue_trusted_request_limit_scope(root),
            )
            for root in roots
        ]
    )
    assert all(
        item.request_limit_reservation_evidence is not None
        and item.request_limit_reservation_evidence.request_limit_count_before == 3
        for item in next_reservations
    )
    for reservation in next_reservations:
        await manager.release(reservation)


@pytest.mark.asyncio
async def test_multi_root_budget_recovery_failure_is_atomic(tmp_path) -> None:
    roots = ("family-a-request", "family-b-request")
    records = tuple(
        sorted(
            (_shared_recovery_usage(root, root_scope=root, count_before=0) for root in roots),
            key=lambda item: item.request_id,
        )
    )
    manager, ledger = _recovery_manager(tmp_path, records)
    before = ledger.snapshot()
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        shared_request_limit_roots=((roots[0], 0), (roots[1], 1)),
    )

    with pytest.raises(BudgetReservationStateError, match="shared recovery request-limit"):
        await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert manager.recovery_required
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_multi_root_budget_recovery_adopts_later_active_attempt_on_exact_root(
    tmp_path,
) -> None:
    roots = ("family-a-request", "family-b-request")
    records = tuple(_shared_recovery_usage(root, root_scope=root, count_before=0) for root in roots)
    manager, ledger = _recovery_manager(tmp_path, records)
    active_request_id = "family-b-request.child-active"
    active_cost = Decimal("0.000011")
    ledger.reserve(active_request_id, active_cost)
    active_attempt = SimpleNamespace(
        request_id=active_request_id,
        logical_request_id=active_request_id,
        task_id="family-b-child-active",
        requested_model="author/exact-model",
        role="source_audit",
        status=SimpleNamespace(value="adopted_proven_pre_send"),
        reserved_cost_usd_exact=active_cost,
        accounted_cost_usd_exact=Decimal(0),
        request_limit_scope=roots[1],
        request_limit_count_before=1,
        request_limit_count_after=2,
        request_limit_maximum=10,
    )
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        non_usage_attempts=(active_attempt,),
        shared_request_limit_roots=tuple((root, 0) for root in roots),
    )

    await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    adopted = await manager.reserve(
        active_request_id,
        "source_audit",
        "x",
        exact_model_id="author/exact-model",
        planned_prompt_tokens=1,
        planned_visible_output_tokens=1,
        planned_reasoning_tokens=0,
        planned_completion_tokens=1,
        request_token_plan_sha256="a" * 64,
        request_limit_scope=_issue_trusted_request_limit_scope(roots[1]),
    )
    assert adopted.request_limit_reservation_evidence is not None
    assert adopted.request_limit_reservation_evidence.request_limit_count_before == 1
    assert adopted.request_limit_reservation_evidence.request_limit_count_after == 2
    await manager.release(adopted)
    next_first_root = await manager.reserve(
        "family-a-request.child-1",
        "source_audit",
        "x",
        exact_model_id="author/exact-model",
        planned_prompt_tokens=1,
        planned_visible_output_tokens=1,
        planned_reasoning_tokens=0,
        planned_completion_tokens=1,
        request_token_plan_sha256="b" * 64,
        request_limit_scope=_issue_trusted_request_limit_scope(roots[0]),
    )
    assert next_first_root.request_limit_reservation_evidence is not None
    assert next_first_root.request_limit_reservation_evidence.request_limit_count_before == 1
    await manager.release(next_first_root)


def test_multi_root_budget_recovery_coordinates_are_bounded_and_compatible() -> None:
    record = _shared_recovery_usage(
        "family-root-request",
        root_scope="family-root-request",
        count_before=0,
    )
    records = (record,)

    _issue_trusted_budget_recovery_scope(
        records,
        shared_request_limit_scope="family-root-request",
        shared_request_limit_count_before=0,
    )
    with pytest.raises(BudgetReservationStateError, match="cannot mix"):
        _issue_trusted_budget_recovery_scope(
            records,
            shared_request_limit_roots=(("family-a-request", 0),),
            shared_request_limit_scope="family-root-request",
            shared_request_limit_count_before=0,
        )
    with pytest.raises(BudgetReservationStateError, match="invalid or exceed bounds"):
        _issue_trusted_budget_recovery_scope(
            records,
            shared_request_limit_roots=tuple(
                (f"family-{index:02d}-request", 0) for index in range(17)
            ),
        )
    with pytest.raises(BudgetReservationStateError, match="invalid or exceed bounds"):
        _issue_trusted_budget_recovery_scope(
            records,
            shared_request_limit_roots=(("family-b-request", 0), ("family-a-request", 0)),
        )


@pytest.mark.asyncio
async def test_multi_root_budget_recovery_rejects_more_than_48_bound_records(tmp_path) -> None:
    roots = tuple(f"family-{index:02d}-request" for index in range(16))
    records = tuple(
        sorted(
            (
                _shared_recovery_usage(
                    root if ordinal == 0 else f"{root}.child-{ordinal}",
                    root_scope=root,
                    count_before=ordinal,
                )
                for root_index, root in enumerate(roots)
                for ordinal in range(4 if root_index == 0 else 3)
            ),
            key=lambda item: item.request_id,
        )
    )
    assert len(records) == 49
    manager, ledger = _recovery_manager(tmp_path, records)
    before = ledger.snapshot()
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        shared_request_limit_roots=tuple((root, 0) for root in roots),
    )

    with pytest.raises(BudgetReservationStateError, match="exceeds its compiled bound"):
        await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert manager.recovery_required
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_budget_recovery_restores_mixed_ordinary_and_shared_root_usage(tmp_path) -> None:
    root_scope = "family-root-request"
    ordinary_scope = "ordinary-task-request"
    records = tuple(
        sorted(
            (
                _shared_recovery_usage(
                    root_scope,
                    root_scope=root_scope,
                    count_before=0,
                ),
                _shared_recovery_usage(
                    "family-root-request.child-a",
                    root_scope=root_scope,
                    count_before=1,
                ),
                _shared_recovery_usage(
                    ordinary_scope,
                    root_scope=ordinary_scope,
                    count_before=0,
                ),
            ),
            key=lambda item: item.request_id,
        )
    )
    manager, _ledger = _recovery_manager(tmp_path, records)
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        shared_request_limit_scope=root_scope,
        shared_request_limit_count_before=0,
    )

    await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    shared_next = await manager.reserve(
        "family-root-request.child-b",
        "source_audit",
        "x",
        exact_model_id="author/exact-model",
        planned_prompt_tokens=1,
        planned_visible_output_tokens=1,
        planned_reasoning_tokens=0,
        planned_completion_tokens=1,
        request_token_plan_sha256="a" * 64,
        request_limit_scope=_issue_trusted_request_limit_scope(root_scope),
    )
    ordinary_next = await manager.reserve(
        "ordinary-task-request.attempt-2",
        "source_audit",
        "x",
        exact_model_id="author/exact-model",
        planned_prompt_tokens=1,
        planned_visible_output_tokens=1,
        planned_reasoning_tokens=0,
        planned_completion_tokens=1,
        request_token_plan_sha256="b" * 64,
        request_limit_scope=_issue_trusted_request_limit_scope(ordinary_scope),
    )
    assert shared_next.request_limit_reservation_evidence is not None
    assert shared_next.request_limit_reservation_evidence.request_limit_count_before == 2
    assert ordinary_next.request_limit_reservation_evidence is not None
    assert ordinary_next.request_limit_reservation_evidence.request_limit_count_before == 1
    await manager.release(shared_next)
    await manager.release(ordinary_next)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ("gap", "duplicate", "wrong_root", "wrong_start", "maximum"),
)
async def test_shared_budget_recovery_rejects_chain_drift(tmp_path, case: str) -> None:
    root_scope = "family-root-request"
    first_count = 0
    second_count = 1
    third_count = 2
    second_root = root_scope
    second_maximum = 10
    claim_start = 0
    if case == "gap":
        second_count = 2
        third_count = 3
    elif case == "duplicate":
        third_count = 1
    elif case == "wrong_root":
        second_root = "different-root-request"
    elif case == "wrong_start":
        claim_start = 1
    elif case == "maximum":
        second_maximum = 11
    records = tuple(
        sorted(
            (
                _shared_recovery_usage(
                    root_scope,
                    root_scope=root_scope,
                    count_before=first_count,
                ),
                _shared_recovery_usage(
                    "family-root-request.child-a",
                    root_scope=second_root,
                    count_before=second_count,
                    maximum=second_maximum,
                ),
                _shared_recovery_usage(
                    "family-root-request.child-b",
                    root_scope=root_scope,
                    count_before=third_count,
                ),
            ),
            key=lambda item: item.request_id,
        )
    )
    manager, ledger = _recovery_manager(tmp_path, records)
    before = ledger.snapshot()
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        shared_request_limit_scope=root_scope,
        shared_request_limit_count_before=claim_start,
    )

    with pytest.raises(BudgetReservationStateError, match="shared recovery request-limit"):
        await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert manager.recovery_required
    assert ledger.snapshot() == before


def test_shared_budget_recovery_rejects_swapped_record_inventory_before_restore() -> None:
    root_scope = "family-root-request"
    records = (
        _shared_recovery_usage(
            root_scope,
            root_scope=root_scope,
            count_before=0,
        ),
        _shared_recovery_usage(
            "family-root-request.child-a",
            root_scope=root_scope,
            count_before=1,
        ),
    )

    with pytest.raises(BudgetReservationStateError, match="identities must be unique and sorted"):
        _issue_trusted_budget_recovery_scope(
            tuple(reversed(records)),
            shared_request_limit_scope=root_scope,
            shared_request_limit_count_before=0,
        )


@pytest.mark.asyncio
async def test_budget_recovery_does_not_infer_shared_scope_from_serialized_usage(
    tmp_path,
) -> None:
    root_scope = "family-root-request"
    records = (
        _shared_recovery_usage(
            root_scope,
            root_scope=root_scope,
            count_before=0,
        ),
        _shared_recovery_usage(
            "family-root-request.child-a",
            root_scope=root_scope,
            count_before=1,
        ),
    )
    manager, ledger = _recovery_manager(tmp_path, records)
    before = ledger.snapshot()
    recovery_scope = _issue_trusted_budget_recovery_scope(records)

    with pytest.raises(BudgetReservationStateError, match="runtime-accountable usage"):
        await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert manager.recovery_required
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_budget_recovery_rejects_nonopaque_or_unknown_shared_authority(tmp_path) -> None:
    root_scope = "family-root-request"
    records = (
        _shared_recovery_usage(
            root_scope,
            root_scope=root_scope,
            count_before=0,
        ),
    )
    manager, ledger = _recovery_manager(tmp_path, records)
    before = ledger.snapshot()

    with pytest.raises(BudgetReservationStateError, match="capability is invalid"):
        await manager.restore_recovered_usage(
            records,
            recovery_scope=object(),  # type: ignore[arg-type]
        )
    with pytest.raises(BudgetReservationStateError, match="supplied together"):
        _issue_trusted_budget_recovery_scope(
            records,
            shared_request_limit_scope=root_scope,
        )
    with pytest.raises(BudgetReservationStateError, match="coordinates are invalid"):
        _issue_trusted_budget_recovery_scope(
            records,
            shared_request_limit_scope="unknown/root",
            shared_request_limit_count_before=0,
        )

    assert manager.recovery_required
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_legacy_single_task_budget_recovery_is_unchanged(tmp_path) -> None:
    root_scope = "legacy-task-request"
    records = (
        _shared_recovery_usage(
            root_scope,
            root_scope=root_scope,
            count_before=0,
        ),
    )
    manager, _ledger = _recovery_manager(tmp_path, records)
    recovery_scope = _issue_trusted_budget_recovery_scope(records)

    await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert not manager.recovery_required
    assert manager.spent_usd_exact == Decimal("0.01")


@pytest.mark.asyncio
async def test_shared_budget_recovery_requires_exact_per_attempt_ledger_cost_join(
    tmp_path,
) -> None:
    root_scope = "family-root-request"
    records = (
        _shared_recovery_usage(
            root_scope,
            root_scope=root_scope,
            count_before=0,
            cost_usd_exact="0.01",
        ),
        _shared_recovery_usage(
            "family-root-request.child-a",
            root_scope=root_scope,
            count_before=1,
            cost_usd_exact="0.02",
        ),
    )
    ledger = AtomicCostLedger.initialize(
        tmp_path / "mismatched-shared-recovery-ledger.json",
        cap_usd=Decimal("1"),
    )
    root_reservation = ledger.reserve(records[0].request_id, Decimal("0.10"))
    ledger.reconcile(root_reservation, Decimal("0.01"))
    child_reservation = ledger.reserve(records[1].request_id, Decimal("0.10"))
    ledger.reconcile(child_reservation, Decimal("0.03"))
    manager = BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
    )
    before = ledger.snapshot()
    recovery_scope = _issue_trusted_budget_recovery_scope(
        records,
        shared_request_limit_scope=root_scope,
        shared_request_limit_count_before=0,
    )

    with pytest.raises(BudgetReservationStateError, match="differs from recovered usage cost"):
        await manager.restore_recovered_usage(records, recovery_scope=recovery_scope)

    assert manager.recovery_required
    assert ledger.snapshot() == before


def _accepted_quote_budget_fixture(
    tmp_path,
    config_factory,
    *,
    run_hard_ceiling_usd_exact: str,
    baseline_spent_usd_exact: str = "0",
):
    from tests.unit.test_prepurchase_quote import _quote_fixture

    cap = Decimal(baseline_spent_usd_exact) + Decimal(run_hard_ceiling_usd_exact)
    return _quote_fixture(
        tmp_path,
        config_factory,
        seed="budget-accepted-quote",
        cap_usd=format(cap, "f"),
        baseline_spent_usd_exact=baseline_spent_usd_exact,
    )


def _quoted_budget_manager(
    ledger: AtomicCostLedger,
    accepted_quote,
) -> BudgetManager:
    return BudgetManager(
        total_usd=1,
        max_output_tokens=10,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
        accepted_quote=accepted_quote,
    )


def _quoted_request_bound(quote_data) -> EndpointRequestCostBound:
    envelope = quote_data.preflight.task_envelopes[0]
    return EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=envelope.requested_model,
        provider_endpoint=envelope.provider_endpoint,
        request_material="quoted-request",
        pricing={
            "completion": "0",
            "prompt": "0",
            "request": "0.1",
        },
        maximum_units={
            "completion": envelope.maximum_completion_tokens_per_attempt,
            "prompt": envelope.maximum_prompt_tokens_per_attempt,
            "request": 1,
        },
    )


def _quoted_retry_policy_sha256(quote_data) -> str:
    return quote_data.quote.retry_policy.policy_sha256


def _quoted_portfolio_slot(
    quote_data,
    *,
    attempt_ordinal: int,
) -> PortfolioTaskSlot:
    envelope = quote_data.preflight.task_envelopes[0]
    request_id = envelope.attempt_request_ids[attempt_ordinal - 1]
    return PortfolioTaskSlot(
        task_id=envelope.scheduler_task_id,
        logical_request_id=envelope.scheduler_logical_request_id,
        attempt_ordinal=attempt_ordinal,
        request_id=request_id,
        role=envelope.request_role,
        exact_model_id=envelope.requested_model,
        provider_endpoint=envelope.provider_endpoint,
        endpoint_policy_snapshot_sha256=envelope.endpoint_policy_snapshot_sha256,
        endpoint_policy_pricing_sha256=envelope.endpoint_policy_pricing_sha256,
        endpoint_pricing_snapshot_sha256=envelope.endpoint_pricing_snapshot_sha256,
        envelope_recipe_sha256=envelope.request_envelope_recipe_sha256,
        planned_prompt_tokens=envelope.maximum_prompt_tokens_per_attempt,
        planned_visible_output_tokens=envelope.maximum_visible_output_tokens_per_attempt,
        planned_reasoning_tokens=envelope.maximum_reasoning_tokens_per_attempt,
        planned_completion_tokens=envelope.maximum_completion_tokens_per_attempt,
        maximum_cost_usd=Decimal(envelope.maximum_cost_usd_per_attempt_exact),
    )


def _quoted_ceiling_bound(ceiling) -> EndpointRequestCostBound:
    assert ceiling.requested_model is not None
    assert ceiling.provider_endpoint is not None
    return EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=ceiling.requested_model,
        provider_endpoint=ceiling.provider_endpoint,
        request_material=f"quoted {ceiling.task_class.value} request",
        pricing={"completion": "0", "prompt": "0", "request": "0.1"},
        maximum_units={
            "completion": ceiling.maximum_output_tokens_per_attempt,
            "prompt": ceiling.maximum_input_tokens_per_attempt,
            "request": 1,
        },
    )


@pytest.mark.asyncio
async def test_accepted_quote_allows_exact_ceiling_and_exposes_constraint_hashes(
    tmp_path,
    config_factory,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.100000000000000001",
    )
    ledger = quote_data.ledger
    accepted = quote_data.acceptance
    manager = _quoted_budget_manager(ledger, accepted)

    envelope = quote_data.preflight.task_envelopes[0]
    reservation = await manager.reserve(
        "quoted-request",
        envelope.request_role,
        "quoted-request",
        endpoint_cost_bound=_quoted_request_bound(quote_data),
        model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
    )

    assert manager.accepted_quote_sha256 == accepted.quote_sha256
    assert manager.accepted_quote_acceptance_sha256 == accepted.acceptance_sha256
    assert manager.accepted_quote_retry_policy_sha256 == (
        quote_data.quote.retry_policy.policy_sha256
    )
    assert manager.accepted_quote_run_hard_ceiling_usd_exact == Decimal("0.100000000000000001")
    assert manager.effective_total_usd_exact == Decimal("0.100000000000000001")
    assert manager.remaining_usd == 1e-18
    assert ledger.snapshot().active_reserved_usd == Decimal("0.1")
    await manager.release(reservation)


@pytest.mark.asyncio
async def test_accepted_quote_rejects_equal_total_split_retry_policy_before_reservation(
    tmp_path,
    config_factory,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.1",
    )
    manager = _quoted_budget_manager(quote_data.ledger, quote_data.acceptance)
    before = quote_data.ledger.snapshot()
    swapped_policy = ModelRetryPolicy.build(
        transient_retry_limit=0,
        schema_validation_retry_limit=1,
    )

    assert swapped_policy.maximum_attempts == quote_data.quote.retry_policy.maximum_attempts
    assert swapped_policy.policy_sha256 != quote_data.quote.retry_policy.policy_sha256
    with pytest.raises(BudgetReservationStateError, match="retry policy differs"):
        await manager.reserve(
            "quoted-policy-drift",
            quote_data.preflight.task_envelopes[0].request_role,
            "quoted-request",
            endpoint_cost_bound=_quoted_request_bound(quote_data),
            model_retry_policy_sha256=swapped_policy.policy_sha256,
        )

    assert quote_data.ledger.snapshot() == before
    assert manager.reserved_usd == 0
    assert manager._issued == {}


@pytest.mark.asyncio
async def test_accepted_quote_guard_retarget_and_kwarg_injection_fail_before_reservation(
    tmp_path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.1",
    )
    manager = _quoted_budget_manager(quote_data.ledger, quote_data.acceptance)
    before = quote_data.ledger.snapshot()

    def forged_guard(*_args: object, **_kwargs: object) -> None:
        return None

    original_guard = budgets_module._require_accepted_quote_request
    monkeypatch.setattr(
        budgets_module,
        "globals",
        lambda: {"_require_accepted_quote_request": original_guard},
        raising=False,
    )
    monkeypatch.setattr(budgets_module, "_require_accepted_quote_request", forged_guard)
    with pytest.raises(BudgetReservationStateError, match="guard provenance"):
        await manager.reserve(
            "quoted-guard-bypass",
            quote_data.preflight.task_envelopes[0].request_role,
            "quoted-request",
            endpoint_cost_bound=_quoted_request_bound(quote_data),
            model_retry_policy_sha256="0" * 64,
            _accepted_quote_request_guard=forged_guard,
        )

    assert quote_data.ledger.snapshot() == before
    assert manager.reserved_usd == 0
    assert manager._issued == {}


@pytest.mark.asyncio
async def test_accepted_quote_rejects_one_cost_atom_over_without_ledger_mutation(
    tmp_path,
    config_factory,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.1",
    )
    ledger = quote_data.ledger
    accepted = quote_data.acceptance
    manager = _quoted_budget_manager(ledger, accepted)
    before = ledger.snapshot()

    envelope = quote_data.preflight.task_envelopes[0]
    mismatched_bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=envelope.requested_model,
        provider_endpoint=envelope.provider_endpoint,
        request_material="quoted-request",
        pricing={"completion": "0", "prompt": "0", "request": "0.100000000000000001"},
        maximum_units={"completion": 50, "prompt": 100, "request": 1},
    )
    with pytest.raises(BudgetReservationStateError, match="differs from the accepted quote"):
        await manager.reserve(
            "quoted-request",
            envelope.request_role,
            "quoted-request",
            endpoint_cost_bound=mismatched_bound,
            model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
        )

    assert ledger.snapshot() == before


def test_accepted_quote_effective_total_adds_exact_baseline_spend(
    tmp_path,
    config_factory,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.3",
        baseline_spent_usd_exact="0.2",
    )
    manager = _quoted_budget_manager(quote_data.ledger, quote_data.acceptance)

    assert manager.spent_usd_exact == Decimal("0.2")
    assert manager.effective_total_usd_exact == Decimal("0.5")
    assert manager.remaining_usd == 0.3
    assert manager.recovery_required


@pytest.mark.parametrize("drift", ("spent", "terminal_snapshot"))
def test_accepted_quote_rejects_ledger_baseline_drift_without_mutation(
    tmp_path,
    config_factory,
    drift: str,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.1",
    )
    ledger = quote_data.ledger
    accepted = quote_data.acceptance
    reservation = ledger.reserve("drift-request", Decimal("0.01"))
    if drift == "spent":
        ledger.reconcile(reservation, Decimal("0.01"))
    else:
        ledger.release(reservation, reason=ReleaseReason.CANCELLED_BEFORE_SEND)
    before = ledger.snapshot()

    with pytest.raises(BudgetReservationStateError, match="baseline differs"):
        _quoted_budget_manager(ledger, accepted)

    assert ledger.snapshot() == before


@pytest.mark.parametrize("active_kind", ("ordinary", "portfolio"))
def test_accepted_quote_rejects_active_reserve_or_hold_without_mutation(
    tmp_path,
    config_factory,
    active_kind: str,
) -> None:
    from mmaudit.orchestration.cost_ledger import PortfolioAttemptSlot

    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.1",
    )
    ledger = quote_data.ledger
    accepted = quote_data.acceptance
    if active_kind == "ordinary":
        ledger.reserve("active-request", Decimal("0.01"))
    else:
        ledger.reserve_portfolio(
            "1" * 64,
            (PortfolioAttemptSlot("active-request", Decimal("0.01")),),
        )
    before = ledger.snapshot()

    with pytest.raises(BudgetReservationStateError, match="zero-active-reservation"):
        _quoted_budget_manager(ledger, accepted)

    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_accepted_quote_portfolio_reservation_uses_exact_incremental_ceiling(
    tmp_path,
    config_factory,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.2",
    )
    ledger = quote_data.ledger
    accepted = quote_data.acceptance
    manager = _quoted_budget_manager(ledger, accepted)
    slots = (
        _quoted_portfolio_slot(quote_data, attempt_ordinal=1),
        _quoted_portfolio_slot(quote_data, attempt_ordinal=2),
    )

    portfolio = await manager.reserve_portfolio("2" * 64, slots)

    assert ledger.snapshot().active_reserved_usd == Decimal("0.2")
    await manager.release_portfolio(portfolio)


@pytest.mark.asyncio
async def test_accepted_quote_portfolio_rejects_one_atom_over_without_mutation(
    tmp_path,
    config_factory,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.2",
    )
    ledger = quote_data.ledger
    accepted = quote_data.acceptance
    manager = _quoted_budget_manager(ledger, accepted)
    before = ledger.snapshot()
    first = _quoted_portfolio_slot(quote_data, attempt_ordinal=1)
    slots = (
        first,
        replace(
            first,
            task_id="second-task",
            logical_request_id="second-request",
            request_id="second-request",
        ),
        replace(
            first,
            task_id="third-task",
            logical_request_id="third-request",
            request_id="third-request",
        ),
    )

    with pytest.raises(BudgetReservationStateError, match="accepted quote route ceiling"):
        await manager.reserve_portfolio("3" * 64, slots)

    assert ledger.snapshot() == before


def test_unaccepted_quote_cannot_install_a_budget_constraint(
    tmp_path,
    config_factory,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.1",
    )
    ledger = quote_data.ledger
    accepted = quote_data.acceptance
    before = ledger.snapshot()

    with pytest.raises(BudgetReservationStateError, match="accepted pre-purchase quote type"):
        _quoted_budget_manager(ledger, accepted.quote)

    assert ledger.snapshot() == before


def test_accepted_quote_requires_manager_total_to_cover_baseline_plus_ceiling(
    tmp_path,
    config_factory,
) -> None:
    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="0.2",
    )
    ledger = quote_data.ledger
    accepted = quote_data.acceptance
    before = ledger.snapshot()

    with pytest.raises(BudgetReservationStateError, match="manager total cannot cover"):
        BudgetManager(
            total_usd=0.1,
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=10,
            atomic_ledger=ledger,
            accepted_quote=accepted,
        )

    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_accepted_quote_rejects_self_hashed_low_price_route_against_live_pricing(
    tmp_path,
    config_factory,
) -> None:
    from mmaudit.models.prepurchase_quote import (
        PrepurchaseQuoteTaskCeiling,
        PrepurchaseQuoteTaskClass,
        accept_prepurchase_quote,
        build_prepurchase_quote,
    )

    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="1",
    )
    source = next(
        item
        for item in quote_data.ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
    )
    assert source.request_role is not None
    assert source.requested_model is not None
    assert source.request_envelope_recipe_sha256 is not None
    assert source.endpoint_policy_snapshot_sha256 is not None
    assert source.endpoint_policy_pricing_sha256 is not None
    assert source.provider_endpoint is not None
    low_bound = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=source.requested_model,
        provider_endpoint=source.provider_endpoint,
        request_material="self-hashed low quote",
        pricing={"completion": "0", "prompt": "0", "request": "0.01"},
        maximum_units={"completion": 50, "prompt": 100, "request": 1},
    )
    low_ceiling = PrepurchaseQuoteTaskCeiling.build(
        task_class=source.task_class,
        request_role=source.request_role,
        requested_model=source.requested_model,
        request_envelope_recipe_sha256=source.request_envelope_recipe_sha256,
        endpoint_policy_snapshot_sha256=source.endpoint_policy_snapshot_sha256,
        endpoint_policy_pricing_sha256=source.endpoint_policy_pricing_sha256,
        provider_endpoint=source.provider_endpoint,
        endpoint_pricing_snapshot_sha256=low_bound.pricing_snapshot_sha256,
        standard_task_count=source.standard_task_count,
        maximum_task_count=source.maximum_task_count,
        standard_attempts_per_task=source.standard_attempts_per_task,
        maximum_attempts_per_task=source.maximum_attempts_per_task,
        maximum_input_tokens_per_attempt=source.maximum_input_tokens_per_attempt,
        maximum_output_tokens_per_attempt=source.maximum_output_tokens_per_attempt,
        maximum_cost_usd_per_attempt_exact="0.01",
        standard_wall_clock_seconds_per_task=source.standard_wall_clock_seconds_per_task,
        maximum_wall_clock_seconds_per_task=source.maximum_wall_clock_seconds_per_task,
    )
    forged_quote = build_prepurchase_quote(
        campaign_manifest=quote_data.manifest,
        solidity_shard_inventory=quote_data.inventory,
        portfolio_preflight=quote_data.preflight,
        local_analysis_ceiling=quote_data.local_analysis,
        retry_policy=quote_data.quote.retry_policy,
        task_ceilings=tuple(
            low_ceiling if item == source else item for item in quote_data.ceilings
        ),
    )
    accepted = accept_prepurchase_quote(
        forged_quote,
        accepted_at=quote_data.acceptance.accepted_at,
    )
    manager = _quoted_budget_manager(quote_data.ledger, accepted)
    live_bound = _quoted_ceiling_bound(source)
    request_material = f"quoted {source.task_class.value} request"
    before = quote_data.ledger.snapshot()

    with pytest.raises(BudgetReservationStateError, match="differs from the accepted quote"):
        await manager.reserve(
            "candidate-price-drift",
            f"candidate_falsifier:{'a' * 64}:reviewer_1",
            request_material,
            endpoint_cost_bound=live_bound,
            model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
        )

    assert quote_data.ledger.snapshot() == before


@pytest.mark.asyncio
async def test_accepted_quote_normalizes_only_exact_candidate_reviewer_roles(
    tmp_path,
    config_factory,
) -> None:
    from mmaudit.models.prepurchase_quote import PrepurchaseQuoteTaskClass

    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="1",
    )
    ceiling = next(
        item
        for item in quote_data.ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
    )
    manager = _quoted_budget_manager(quote_data.ledger, quote_data.acceptance)
    bound = _quoted_ceiling_bound(ceiling)
    request_material = f"quoted {ceiling.task_class.value} request"
    valid_role = f"candidate_falsifier:{'b' * 64}:reviewer_2"
    reservation = await manager.reserve(
        "candidate-role-valid",
        valid_role,
        request_material,
        endpoint_cost_bound=bound,
        model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
    )
    await manager.release(reservation)
    before = quote_data.ledger.snapshot()

    with pytest.raises(BudgetReservationStateError, match="differs from the accepted quote"):
        await manager.reserve(
            "candidate-role-invalid",
            f"candidate_falsifier:{'b' * 64}:reviewer_3",
            request_material,
            endpoint_cost_bound=bound,
            model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
        )

    assert quote_data.ledger.snapshot() == before


@pytest.mark.asyncio
async def test_accepted_quote_route_capacity_failure_does_not_consume_or_mutate(
    tmp_path,
    config_factory,
) -> None:
    from mmaudit.models.prepurchase_quote import PrepurchaseQuoteTaskClass

    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="1",
    )
    ceiling = next(
        item
        for item in quote_data.ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
    )
    manager = _quoted_budget_manager(quote_data.ledger, quote_data.acceptance)
    bound = _quoted_ceiling_bound(ceiling)
    request_material = f"quoted {ceiling.task_class.value} request"
    role = f"candidate_falsifier:{'c' * 64}:reviewer_1"
    for index in range(ceiling.worst_case_request_count):
        reservation = await manager.reserve(
            f"candidate-capacity-{index}",
            role,
            request_material,
            endpoint_cost_bound=bound,
            model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
        )
        await manager.release(reservation)
    before = quote_data.ledger.snapshot()

    for identifier in ("candidate-capacity-over-a", "candidate-capacity-over-b"):
        with pytest.raises(BudgetExhaustedError, match="route request ceiling is exhausted"):
            await manager.reserve(
                identifier,
                role,
                request_material,
                endpoint_cost_bound=bound,
                model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
            )
        assert quote_data.ledger.snapshot() == before


@pytest.mark.asyncio
async def test_accepted_quote_recovery_uses_separate_global_request_capacity(
    tmp_path,
    config_factory,
) -> None:
    from mmaudit.models.prepurchase_quote import PrepurchaseQuoteTaskClass

    quote_data = _accepted_quote_budget_fixture(
        tmp_path,
        config_factory,
        run_hard_ceiling_usd_exact="1",
    )
    primary = next(
        item
        for item in quote_data.ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.ADVERSARIAL_CROSS_EXAMINATION
    )
    recovery = next(
        item
        for item in quote_data.ceilings
        if item.task_class is PrepurchaseQuoteTaskClass.TRUNCATION_RECOVERY
    )
    manager = _quoted_budget_manager(quote_data.ledger, quote_data.acceptance)
    bound = _quoted_ceiling_bound(primary)
    request_material = f"quoted {primary.task_class.value} request"
    role = f"candidate_falsifier:{'d' * 64}:reviewer_1"
    for index in range(recovery.worst_case_request_count):
        reservation = await manager.reserve(
            f"scheduler-recovery-request-{index:064x}",
            role,
            request_material,
            endpoint_cost_bound=bound,
            model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
        )
        await manager.release(reservation)
    before = quote_data.ledger.snapshot()

    with pytest.raises(BudgetExhaustedError, match="global recovery request ceiling"):
        await manager.reserve(
            f"scheduler-recovery-request-{recovery.worst_case_request_count:064x}",
            role,
            request_material,
            endpoint_cost_bound=bound,
            model_retry_policy_sha256=_quoted_retry_policy_sha256(quote_data),
        )

    assert quote_data.ledger.snapshot() == before
