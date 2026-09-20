"""Synthetic contract-to-budget-to-ledger integration with a local mock transport.

This does not exercise or authorize live OpenRouter admission. Portfolio/recovery,
profile ancestry and provider request/usage adoption remain separate consumers.
"""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from mmaudit.models.route_cost_reservations import ExactRouteCostReservation
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    BudgetReservationStateError,
    EndpointRequestCostBound,
    Reservation,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostLedgerConfigurationError,
    CostReservationOverrunError,
)
from tests.unit.test_route_cost_reservations import BINDINGS, _canonical, _inputs


@pytest.fixture(autouse=True)
def _no_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("contract/ledger integration attempted external execution")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr("mmaudit.operator_secrets.load_operator_secrets", refuse)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", refuse)


def _manager(
    path: Path, *, cap: str = "250", persistent: bool = True
) -> tuple[BudgetManager, AtomicCostLedger | None]:
    ledger = AtomicCostLedger.initialize(path, cap_usd=Decimal(cap)) if persistent else None
    return BudgetManager(
        total_usd=float(cap),
        max_output_tokens=4096,
        conservative_usd_per_million_tokens=1,
        max_requests_per_agent=10,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    ), ledger


def _bound(inputs: dict[str, Any]) -> EndpointRequestCostBound:
    return EndpointRequestCostBound.from_route_cost_reservation(
        ExactRouteCostReservation.build(**inputs),
        request_material=inputs["request_material"],
        **BINDINGS,
    )


async def _reserve(manager: BudgetManager, inputs: dict[str, Any], **overrides: Any) -> Reservation:
    plan = inputs["request_token_plan"]
    values = {
        "identifier": plan.request_id,
        "role": plan.role,
        "prompt": inputs["request_material"],
        "endpoint_cost_bound": _bound(inputs),
        "exact_model_id": plan.route_intersection.exact_model_ids[0],
        "planned_prompt_tokens": plan.prompt_byte_upper_bound_tokens,
        "planned_visible_output_tokens": plan.reserved_output_tokens,
        "planned_reasoning_tokens": plan.reserved_reasoning_tokens,
        "planned_completion_tokens": plan.requested_completion_tokens,
        "request_token_plan_sha256": plan.plan_sha256,
    }
    return await manager.reserve(**{**values, **overrides})


@pytest.mark.asyncio
@pytest.mark.parametrize("actual", ("0", "0.5", "exact", "unknown", "overrun", "overcap"))
async def test_contract_liability_precedes_mock_transport_and_preserves_every_bill(
    tmp_path: Path, actual: str
) -> None:
    """Invariant: liability precedes dispatch; unknown/overrun is never a settled pass."""

    manager, ledger = _manager(tmp_path / "synthetic-ledger.json")
    assert ledger is not None
    inputs = _inputs()
    reservation = await _reserve(manager, inputs)
    assert reservation.persistent is not None
    maximum = reservation.persistent.reserved_usd
    cost = (
        None
        if actual == "unknown"
        else maximum
        if actual == "exact"
        else maximum + Decimal("0.000000000000000001")
        if actual == "overrun"
        else Decimal("250.01")
        if actual == "overcap"
        else Decimal(actual)
    )
    calls = []

    async def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        retained = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250")).snapshot()
        entry = next(item for item in retained.entries if item.request_id == reservation.identifier)
        assert entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        assert entry.actual_cost_usd is None and entry.accounted_cost_usd == maximum
        return httpx.Response(
            200, json={"synthetic_actual_cost": None if cost is None else str(cost)}
        )

    await manager.commit_active_reservation_for_transport(reservation)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        response = await client.post(
            "https://synthetic.invalid/local-only", content=inputs["request_material"]
        )
    assert len(calls) == 1
    billed = response.json()["synthetic_actual_cost"]
    if actual in {"overrun", "overcap"}:
        with pytest.raises(CostReservationOverrunError):
            await manager.reconcile(
                reservation,
                Decimal(billed),
                actual_prompt_tokens=1,
                actual_completion_tokens=1,
                actual_reasoning_tokens=0,
            )
    else:
        await manager.reconcile(
            reservation,
            None if billed is None else Decimal(billed),
            actual_prompt_tokens=1,
            actual_completion_tokens=1,
            actual_reasoning_tokens=0,
        )
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    entry = next(
        item for item in reopened.snapshot().entries if item.request_id == reservation.identifier
    )
    assert entry.actual_cost_usd == cost
    assert entry.accounted_cost_usd == (maximum if cost is None else cost)
    if actual in {"unknown", "overrun", "overcap"}:
        before = ledger.path.read_bytes()
        with pytest.raises(BudgetExhaustedError):
            await _reserve(manager, _inputs(request_id="synthetic-next"))
        assert ledger.path.read_bytes() == before
        assert len(calls) == 1
        with pytest.raises(CostBudgetExceededError):
            reopened.reserve(
                "synthetic-restarted", Decimal("0.01"), require_settled_prior_costs=True
            )
    else:
        following = await _reserve(manager, _inputs(request_id="synthetic-next"))
        await manager.release(following)


@pytest.mark.asyncio
@pytest.mark.parametrize("cap,persistent", (("251", True), ("249", True), ("250", False)))
async def test_reservation_requires_the_exact_fixed_persistent_ceiling(
    tmp_path: Path, cap: str, persistent: bool
) -> None:
    if not persistent:
        with pytest.raises(BudgetReservationStateError, match="durable atomic ledger"):
            _manager(tmp_path / "synthetic-ledger.json", cap=cap, persistent=False)
        assert not (tmp_path / "synthetic-ledger.json").exists()
        return
    manager, ledger = _manager(tmp_path / "synthetic-ledger.json", cap=cap, persistent=persistent)
    before = ledger.path.read_bytes() if ledger is not None else None
    with pytest.raises(BudgetReservationStateError, match="exact ledger"):
        await _reserve(manager, _inputs())
    assert (ledger.path.read_bytes() if ledger is not None else None) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    (
        ("identifier", "other-request"),
        ("role", "other-role"),
        ("request_token_plan_sha256", "f" * 64),
        ("planned_prompt_tokens", 1),
    ),
)
async def test_reserved_request_scope_cannot_drift(tmp_path: Path, field: str, value: Any) -> None:
    manager, ledger = _manager(tmp_path / "synthetic-ledger.json")
    assert ledger is not None
    before = ledger.path.read_bytes()
    with pytest.raises(BudgetReservationStateError):
        await _reserve(manager, _inputs(), **{field: value})
    assert ledger.path.read_bytes() == before


def test_operator_tag_cannot_be_removed_or_replaced_with_legacy_pricing_hash() -> None:
    inputs = _inputs()
    bound = _bound(inputs)
    assert bound.operator_reservation is not None
    with pytest.raises(ValueError, match="snapshot hash"):
        replace(bound, operator_reservation=None)
    legacy = EndpointRequestCostBound.from_endpoint_pricing(
        exact_model_id=bound.exact_model_id,
        provider_endpoint=bound.provider_endpoint,
        request_material=inputs["request_material"],
        pricing={item.pricing_field: item.unit_price_usd for item in bound.components},
        maximum_units={item.pricing_field: item.maximum_units for item in bound.components},
    )
    assert legacy.operator_reservation is None
    assert legacy.pricing_snapshot_sha256 != bound.pricing_snapshot_sha256
    with pytest.raises(ValueError, match="snapshot hash"):
        replace(bound, pricing_snapshot_sha256=legacy.pricing_snapshot_sha256)


@pytest.mark.asyncio
async def test_cancellation_before_commit_releases_only_unsent_liability(tmp_path: Path) -> None:
    manager, ledger = _manager(tmp_path / "synthetic-ledger.json")
    assert ledger is not None
    pending = await _reserve(manager, _inputs())
    await manager.release(pending)
    entry = ledger.snapshot().entries[0]
    assert entry.status is CostEntryStatus.RELEASED
    assert entry.actual_cost_usd is None and entry.accounted_cost_usd == 0
    with pytest.raises(BudgetReservationStateError):
        await manager.commit_active_reservation_for_transport(pending)


@pytest.mark.asyncio
async def test_unknown_bill_can_be_recorded_later_without_erasing_the_reservation(
    tmp_path: Path,
) -> None:
    manager, ledger = _manager(tmp_path / "synthetic-ledger.json")
    assert ledger is not None
    pending = await _reserve(manager, _inputs())
    assert pending.persistent is not None
    await manager.commit_active_reservation_for_transport(pending)
    await manager.reconcile(
        pending, None, actual_prompt_tokens=1, actual_completion_tokens=1, actual_reasoning_tokens=0
    )
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    billed = reopened.reconcile(pending.persistent, Decimal("0.01"))
    assert billed.reserved_usd == pending.persistent.reserved_usd
    assert billed.actual_cost_usd == billed.accounted_cost_usd == Decimal("0.01")


@pytest.mark.asyncio
async def test_concurrent_reservations_conserve_liability(tmp_path: Path) -> None:
    manager, ledger = _manager(tmp_path / "synthetic-ledger.json")
    assert ledger is not None
    pending = await asyncio.gather(
        _reserve(manager, _inputs(request_id="synthetic-one")),
        _reserve(manager, _inputs(request_id="synthetic-two")),
    )
    assert ledger.snapshot().active_reserved_usd == sum(
        (item.persistent.reserved_usd for item in pending if item.persistent is not None),
        Decimal(0),
    )
    for item in pending:
        await manager.release(item)


@pytest.mark.asyncio
@pytest.mark.parametrize("overrun", (False, True))
async def test_pre_reserved_attempt_stops_after_unknown_or_overrun(
    tmp_path: Path, overrun: bool
) -> None:
    manager, ledger = _manager(tmp_path / "synthetic-ledger.json")
    assert ledger is not None
    first = await _reserve(manager, _inputs(request_id="synthetic-first"))
    second = await _reserve(manager, _inputs(request_id="synthetic-second"))
    assert first.persistent is not None
    await manager.commit_active_reservation_for_transport(first)
    if overrun:
        with pytest.raises(CostReservationOverrunError):
            await manager.reconcile(first, first.persistent.reserved_usd + Decimal("0.01"))
    else:
        await manager.reconcile(first, None)
    retained = ledger.path.read_bytes()
    with pytest.raises(CostBudgetExceededError):
        await manager.commit_active_reservation_for_transport(second)
    assert ledger.path.read_bytes() == retained
    assert ledger.active_reservation(second.identifier) == second.persistent
    if not overrun:
        # Later genuine billing clears uncertainty; no unsent reservation was erased.
        ledger.reconcile(first.persistent, Decimal("0.01"))
        await manager.commit_active_reservation_for_transport(second)
        assert ledger.snapshot().entries[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED


@pytest.mark.parametrize("value", (None, 0, 1, "true"))
def test_known_cost_mode_rejects_nonboolean_flags_without_mutation(
    tmp_path: Path, value: Any
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-pending", Decimal("1"))
    retained = ledger.path.read_bytes()
    with pytest.raises(CostLedgerConfigurationError):
        ledger.reserve("synthetic-next", Decimal("1"), require_known_prior_costs=value)
    with pytest.raises(CostLedgerConfigurationError):
        ledger.commit_for_transport(pending, require_known_prior_costs=value)
    assert ledger.path.read_bytes() == retained


def test_known_cost_mode_cannot_waive_or_mix_unknown_cost_allowances(tmp_path: Path) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    pending = ledger.reserve("synthetic-pending", Decimal("1"))
    ledger.commit_for_transport(pending)
    retained = ledger.path.read_bytes()
    for kwargs in (
        {"require_settled_prior_costs": True},
        {"allowed_uncertain_reservations": (pending,)},
    ):
        with pytest.raises(CostLedgerConfigurationError):
            ledger.reserve("synthetic-next", Decimal("1"), require_known_prior_costs=True, **kwargs)
    assert ledger.path.read_bytes() == retained


@pytest.mark.asyncio
async def test_changed_request_body_never_creates_a_ledger_entry(tmp_path: Path) -> None:
    manager, ledger = _manager(tmp_path / "synthetic-ledger.json")
    assert ledger is not None
    inputs = _inputs()
    body = json.loads(inputs["request_material"])
    body["messages"][1]["content"] = "Changed synthetic material"
    before = ledger.path.read_bytes()
    with pytest.raises(ValueError, match="exact request material"):
        await _reserve(manager, inputs, prompt=_canonical(body))
    assert ledger.path.read_bytes() == before
