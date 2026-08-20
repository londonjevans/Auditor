from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from decimal import Decimal, localcontext
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import ContextRequestEvidence, UsageRecord
from mmaudit.models.usage import is_recovery_accountable_usage_record
from mmaudit.orchestration.budgets import (
    AtomicRequestLimitReservationEvidence,
    AtomicTokenReservationEvidence,
    BudgetExhaustedError,
    BudgetManager,
    BudgetReservationStateError,
    EndpointRequestCostBound,
    Reservation,
    TokenReservationOverrunError,
    UnprovenCostBoundError,
    _issue_trusted_budget_recovery_scope,
    _issue_trusted_request_limit_scope,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostReservationOverrunError,
)
from tests.unit.test_usage import _creditable_record, _token_plan_for_record


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
    return (
        BudgetManager(
            total_usd=1,
            max_output_tokens=10,
            conservative_usd_per_million_tokens=1,
            max_requests_per_agent=10,
            atomic_ledger=ledger,
            global_input_token_budget=100_000,
            global_output_token_budget=10_000,
        ),
        ledger,
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
