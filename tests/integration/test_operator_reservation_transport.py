"""Actual reservation, request and ledger consumers on sealed synthetic transport only."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import mmaudit.operator_secrets as secrets_module
from mmaudit.models.authenticated_runner_smoke import _require_usage_preview_join
from mmaudit.models.coverage_planning import ModelPortfolioTaskKind
from mmaudit.models.openrouter import (
    OpenRouterError,
    preview_openrouter_structured_request_cost,
    require_operator_cost_preview_usage,
    trusted_preview_model_portfolio_task_resources,
)
from mmaudit.models.route_cost_reservations import operator_cost_attempts_from_usage
from mmaudit.models.scheduler import (
    SchedulerPassKind,
    SchedulerScope,
    SchedulerTaskKind,
    SchedulerTaskPlan,
)
from mmaudit.models.schemas import ModelSurfaceReviewArtifact, UsageRecord
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    BudgetReservationStateError,
    PortfolioTaskSlot,
    _issue_trusted_budget_recovery_scope,
    _issue_trusted_request_limit_scope,
)
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostBudgetExceededError,
    CostEntryStatus,
    CostReservationOverrunError,
    cost_entry_sha256,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.scheduler_support import _synthetic_manifest
from tests.unit.test_openrouter import Answer, _client, _completion_response, _empty_context_package
from tests.unit.test_openrouter_operator_reservations import _reservation_inputs
from tests.unit.test_openrouter_request_cost_preview import _preview


@pytest.fixture(autouse=True)
def local_only(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError(
            "reservation integration must not access providers, secrets or commands"
        )

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(secrets_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)


@pytest.mark.asyncio
async def test_exact_reservation_precedes_dispatch_and_actual_bill_replaces_it(
    config_factory: Any, tmp_path: Path
) -> None:
    """Invariant: no synthetic dispatch occurs without a committed shared-ledger reserve."""

    inputs = _reservation_inputs(config_factory, tmp_path)
    config = inputs["config"]
    preview = _preview(**inputs)
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=config.execution.conservative_usd_per_million_tokens,
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    observed: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        snapshot = ledger.snapshot()
        assert len(snapshot.entries) == 1
        entry = snapshot.entries[0]
        assert entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        assert entry.actual_cost_usd is None
        assert (
            entry.reserved_usd
            == entry.accounted_cost_usd
            == Decimal(preview.maximum_cost_usd_per_attempt_exact)
        )
        assert snapshot.active_reserved_usd == 0
        reservation = budget._issued[preview.logical_request_id]
        assert reservation.endpoint_cost_bound is not None
        contract = reservation.endpoint_cost_bound.operator_reservation
        assert contract is not None
        body = json.loads(request.content)
        assert body["provider"]["max_price"] == {
            item.component.value: item.value for item in contract.provider_capped_subset
        }
        assert "input_cache_write" not in body["provider"]["max_price"]
        assert len(contract.components) == len(contract.exact_pricing) == 4
        observed.append(request)
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    client, http_client, _usage = _client(
        config,
        handler,
        provider_policy=inputs["policy"],
        reasoning_policy=inputs["reasoning_policy"],
        qualification_routing=(),
        budget=budget,
        candidate_revocation_route_constraint=inputs[
            "evidence"
        ].endpoint_snapshot.exact_route_constraint,
    )
    client.register_certification_model_discovery(
        evidence=inputs["evidence"], manifest=inputs["manifest"]
    )
    try:
        result = await client.complete_with_evidence(
            role="model_benchmark",
            models=["alpha/atlas-secure"],
            system_prompt="bounded synthetic system prompt",
            user_prompt="synthetic provider-free request",
            response_model=Answer,
            schema_name="answer",
            logical_request_id=preview.logical_request_id,
            expected_request_cost_preview=preview,
        )
    finally:
        await client.close()
        await http_client.aclose()
    assert result.value.answer == "ok"
    assert len(observed) == 1
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    snapshot = reopened.snapshot()
    assert snapshot.active_reserved_usd == 0
    assert snapshot.entries[0].status is CostEntryStatus.RECONCILED
    assert snapshot.entries[0].actual_cost_usd == snapshot.spent_usd == Decimal("0.01")
    attempts = operator_cost_attempts_from_usage(result.usage_record)
    assert len(attempts) == 1
    assert attempts[0].ledger_entry_sha256 == cost_entry_sha256(snapshot.entries[0])
    assert attempts[0].actual_billed_cost_usd_exact == "0.01"
    assert attempts[0].reservation.policy.provider_enforced_total_ceiling is False
    assert require_operator_cost_preview_usage(result.usage_record, preview) == attempts
    assert _require_usage_preview_join(result.usage_record, preview) == attempts


def _client_for_inputs(inputs: dict[str, Any], ledger: AtomicCostLedger, handler: Any) -> Any:
    config = inputs["config"]
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=config.execution.conservative_usd_per_million_tokens,
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    client, http_client, usage = _client(
        config,
        handler,
        provider_policy=inputs["policy"],
        reasoning_policy=inputs["reasoning_policy"],
        qualification_routing=(),
        budget=budget,
        candidate_revocation_route_constraint=inputs[
            "evidence"
        ].endpoint_snapshot.exact_route_constraint,
    )
    client.register_certification_model_discovery(
        evidence=inputs["evidence"], manifest=inputs["manifest"]
    )
    return client, http_client, usage


async def _complete_reserved(client: Any, preview: Any, *, context_package: Any = None) -> Any:
    return await client.complete_with_evidence(
        role="model_benchmark",
        models=["alpha/atlas-secure"],
        system_prompt="bounded synthetic system prompt",
        user_prompt=render_context(context_package)
        if context_package is not None
        else "synthetic provider-free request",
        context_package=context_package,
        response_model=Answer,
        schema_name="answer",
        logical_request_id=preview.logical_request_id,
        expected_request_cost_preview=preview,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ("missing_bill", "transient", "overrun", "ceiling", "cancelled")
)
async def test_unknown_or_overrun_bill_is_retained_and_blocks_further_work(
    config_factory: Any, tmp_path: Path, failure: str
) -> None:
    """Invariant: unknown or over-reservation liability survives reopen and forbids retry."""

    inputs = _reservation_inputs(config_factory, tmp_path, maximum_attempts=2)
    preview = _preview(**inputs)
    ledger = AtomicCostLedger.initialize(tmp_path / "failure-ledger.json", cap_usd=Decimal("250"))
    observed = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        assert ledger.snapshot().entries[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        if failure == "cancelled":
            raise asyncio.CancelledError("synthetic local cancellation")
        if failure == "transient":
            return httpx.Response(429, json={"error": "synthetic transient"})
        return _completion_response(
            '{"answer":"not creditable"}',
            cost=None if failure == "missing_bill" else 251 if failure == "ceiling" else 0.5,
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    client, http_client, usage = _client_for_inputs(inputs, ledger, handler)
    try:
        expected_error = (
            asyncio.CancelledError
            if failure == "cancelled"
            else (OpenRouterError, CostReservationOverrunError)
        )
        with pytest.raises(expected_error):
            await _complete_reserved(client, preview)
    finally:
        await client.close()
        await http_client.aclose()
    assert len(observed) == 1
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    snapshot = reopened.snapshot()
    assert len(snapshot.entries) == 1
    entry = snapshot.entries[0]
    if failure in {"overrun", "ceiling"}:
        assert entry.status is CostEntryStatus.RESERVATION_OVERRUN
        assert (
            entry.actual_cost_usd
            == entry.accounted_cost_usd
            == (Decimal("251") if failure == "ceiling" else Decimal("0.5"))
        )
        assert snapshot.over_cap is (failure == "ceiling")
    else:
        assert entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        assert entry.actual_cost_usd is None
        assert entry.accounted_cost_usd == entry.reserved_usd
    assert len(usage.records) == 1
    attempts = operator_cost_attempts_from_usage(usage.records[0])
    assert len(attempts) == 1 and attempts[0].ledger_entry_sha256 == cost_entry_sha256(entry)
    assert usage.records[0].status != "success"
    with pytest.raises(CostBudgetExceededError):
        reopened.reserve(
            "prohibited-after-liability", Decimal("0.001"), require_known_prior_costs=True
        )


@pytest.mark.asyncio
async def test_known_bill_schema_retry_reserves_each_attempt_and_conserves_total(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    """Invariant: even same-body retries must reserve and settle every actual bill."""

    inputs = _reservation_inputs(config_factory, tmp_path, maximum_attempts=2, schema_retries=True)
    preview = _preview(**inputs)
    ledger = AtomicCostLedger.initialize(tmp_path / "retry-ledger.json", cap_usd=Decimal("250"))
    observed: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request.content)
        entries = ledger.snapshot().entries
        assert len(entries) == len(observed)
        assert entries[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        if len(observed) == 2:
            assert entries[0].status is CostEntryStatus.RECONCILED
        return _completion_response(
            '{"unexpected":"synthetic schema miss"}' if len(observed) == 1 else '{"answer":"ok"}',
            cost=0.01 if len(observed) == 1 else 0.02,
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    client, http_client, usage = _client_for_inputs(inputs, ledger, handler)
    try:
        result = await _complete_reserved(client, preview)
    finally:
        await client.close()
        await http_client.aclose()
    assert result.value.answer == "ok"
    assert len(observed) == 2 and observed[0] == observed[1]
    assert len(usage.records) == 1
    attempts = operator_cost_attempts_from_usage(result.usage_record)
    assert [item.attempt_request_id for item in attempts] == [
        preview.logical_request_id,
        f"{preview.logical_request_id}:attempt:2",
    ]
    assert [item.actual_billed_cost_usd_exact for item in attempts] == ["0.01", "0.02"]
    assert require_operator_cost_preview_usage(result.usage_record, preview) == attempts
    assert _require_usage_preview_join(result.usage_record, preview) == attempts
    assert (
        ledger.snapshot().spent_usd
        == Decimal(result.usage_record.accounted_cost_usd_exact)
        == Decimal("0.03")
    )


@pytest.mark.asyncio
async def test_later_request_retains_preview_with_actual_budget_position(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    """Invariant: later budget positions do not change an accepted pricing projection."""

    inputs = _reservation_inputs(config_factory, tmp_path, maximum_attempts=2)
    previews = tuple(
        _preview(**inputs, logical_request_id=f"synthetic-sequence-{i}") for i in range(2)
    )
    ledger = AtomicCostLedger.initialize(tmp_path / "sequence-ledger.json", cap_usd=Decimal("250"))

    def handler(_request: httpx.Request) -> httpx.Response:
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    client, http_client, _usage = _client_for_inputs(inputs, ledger, handler)
    try:
        results = [await _complete_reserved(client, preview) for preview in previews]
    finally:
        await client.close()
        await http_client.aclose()
    assert ledger.snapshot().spent_usd == Decimal("0.02")
    first, second = (
        operator_cost_attempts_from_usage(result.usage_record)[0] for result in results
    )
    assert first.reservation.reservation_sha256 != second.reservation.reservation_sha256
    assert (
        previews[0].endpoint_cost_bound_pricing_sha256
        == previews[1].endpoint_cost_bound_pricing_sha256
    )
    assert (
        second.reservation.request_token_plan
        != previews[1].operator_cost_reservation.request_token_plan
    )
    for result, preview in zip(results, previews, strict=True):
        attempts = operator_cost_attempts_from_usage(result.usage_record)
        assert require_operator_cost_preview_usage(result.usage_record, preview) == attempts
        assert _require_usage_preview_join(result.usage_record, preview) == attempts


class _LocalRequestScope:
    def request_ready(self, *, logical_request_id: str, **_values: Any) -> Any:
        return _issue_trusted_request_limit_scope(logical_request_id)

    def request_dispatched(self, *, logical_request_id: str) -> None:
        pass


def _context_preview(inputs: dict[str, Any], package: Any, request_id: str) -> Any:
    config = inputs["config"]
    return preview_openrouter_structured_request_cost(
        execution=config.execution,
        privacy=config.privacy,
        token_budgets=config.token_budgets,
        provider_policy=inputs["policy"],
        reasoning_policy=inputs["reasoning_policy"],
        discovery_manifest=inputs["manifest"],
        discovery_evidence=inputs["evidence"],
        role="model_benchmark",
        system_prompt="bounded synthetic system prompt",
        user_prompt=render_context(package),
        response_model=Answer,
        schema_name="answer",
        logical_request_id=request_id,
        context_package=package,
    )


def _slot(preview: Any) -> PortfolioTaskSlot:
    return PortfolioTaskSlot(
        task_id=preview.logical_request_id,
        logical_request_id=preview.logical_request_id,
        attempt_ordinal=1,
        request_id=preview.logical_request_id,
        role=preview.role,
        exact_model_id=preview.exact_model_id,
        provider_endpoint=preview.provider_endpoint,
        endpoint_policy_snapshot_sha256=preview.endpoint_policy_snapshot_sha256,
        endpoint_policy_pricing_sha256=preview.endpoint_policy_pricing_sha256,
        endpoint_pricing_snapshot_sha256=preview.endpoint_cost_bound_pricing_sha256,
        envelope_recipe_sha256=preview.preview_sha256,
        planned_prompt_tokens=preview.maximum_priced_prompt_units,
        planned_visible_output_tokens=preview.reserved_output_tokens,
        planned_reasoning_tokens=preview.reserved_reasoning_tokens,
        planned_completion_tokens=preview.requested_completion_tokens,
        maximum_cost_usd=Decimal(preview.maximum_cost_usd_per_attempt_exact),
    )


def _planned_portfolio(client: Any) -> tuple[Any, tuple[PortfolioTaskSlot, ...]]:
    """Exercise real task planning; do not fabricate a later request's pricing bound."""

    manifest = _synthetic_manifest("operator-reservation-portfolio")
    task = SchedulerTaskPlan.build(
        manifest=manifest,
        pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
        scope=SchedulerScope.single_shard(manifest.shard_ids[0]),
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        task_key="synthetic-cost-task",
        role="model_benchmark",
        requested_model="alpha/atlas-secure",
        root_lineage="sha256:" + "b" * 64,
        input_sha256="c" * 64,
        prompt_sha256="d" * 64,
        system_prompt_sha256="a" * 64,
        normalizer_sha256="f" * 64,
        response_schema_sha256="e" * 64,
        model_surface_review_request_manifest_sha256=(
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(())
        ),
    )
    envelope = trusted_preview_model_portfolio_task_resources(
        client,
        task_kind=ModelPortfolioTaskKind.SOURCE_AUDIT,
        scheduler_task=task,
        campaign_manifest=manifest,
    )
    slots = tuple(
        PortfolioTaskSlot(
            task_id=envelope.scheduler_task_id,
            logical_request_id=envelope.scheduler_logical_request_id,
            request_id=request_id,
            attempt_ordinal=index,
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
        for index, request_id in enumerate(envelope.attempt_request_ids, 1)
    )
    return envelope, slots


@pytest.mark.asyncio
@pytest.mark.parametrize("component", ("input_cache_write", "internal_reasoning", "web_search"))
async def test_whole_task_reservation_planning_covers_actual_requests_and_billed_retry(
    config_factory: Any, tmp_path: Path, component: str
) -> None:
    """Invariant: task holds dominate exact attempts and preserve each retry's actual bill."""

    inputs = _reservation_inputs(
        config_factory, tmp_path, component=component, maximum_attempts=2, schema_retries=True
    )
    ledger = AtomicCostLedger.initialize(tmp_path / "planned-task.json", cap_usd=Decimal("250"))
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        entries = ledger.snapshot().entries
        assert entries[-1].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        calls.append(request)
        return _completion_response(
            '{"answer":"ok"}' if len(calls) == 2 else '{"unexpected":"synthetic schema miss"}',
            cost=0.02 if len(calls) == 2 else 0.01,
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    client, http_client, usage = _client_for_inputs(inputs, ledger, handler)
    client.bind_request_lifecycle_observer(_LocalRequestScope())
    try:
        before = ledger.snapshot()
        envelope, slots = _planned_portfolio(client)
        assert _planned_portfolio(client) == (envelope, slots)
        assert not envelope.authorizes_dispatch and not envelope.grants_review_credit
        assert ledger.snapshot() == before and not calls and not usage.records
        preview = _preview(**inputs, logical_request_id=envelope.scheduler_logical_request_id)
        assert envelope.endpoint_pricing_snapshot_sha256 == (
            preview.endpoint_cost_bound_pricing_sha256
        )
        assert envelope.maximum_prompt_tokens_per_attempt >= preview.maximum_priced_prompt_units
        assert Decimal(envelope.maximum_cost_usd_per_attempt_exact) >= Decimal(
            preview.maximum_cost_usd_per_attempt_exact
        )
        portfolio = await client.budget.reserve_portfolio(envelope.envelope_sha256, slots)
        assert ledger.snapshot().held_portfolio_usd == Decimal(envelope.maximum_cost_usd_exact)
        async with client.budget.portfolio_task_scope(portfolio, slots[0].task_id):
            result = await _complete_reserved(client, preview)
        await client.budget.release_portfolio(portfolio)
        assert result.value.answer == "ok" and len(calls) == 2
        attempts = operator_cost_attempts_from_usage(result.usage_record)
        assert [a.actual_billed_cost_usd_exact for a in attempts] == ["0.01", "0.02"]
        assert all(
            Decimal(a.reserved_cost_usd_exact) <= slots[0].maximum_cost_usd for a in attempts
        )
        assert ledger.snapshot().held_portfolio_usd == 0
        assert ledger.snapshot().spent_usd == Decimal("0.03")
    finally:
        await client.close()
        await http_client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ("pricing_drift", "underfunded", "unknown_after_hold"))
async def test_planned_slots_do_not_bypass_exact_cost_or_unknown_bill_stops(
    config_factory: Any, tmp_path: Path, failure: str
) -> None:
    """Invariant: even a pre-funded task cannot dispatch with wrong costs or unknown bills."""

    inputs = _reservation_inputs(config_factory, tmp_path)
    ledger = AtomicCostLedger.initialize(tmp_path / "planned-refusal.json", cap_usd=Decimal("250"))

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("invalid planned slot must fail before transport")

    client, http_client, usage = _client_for_inputs(inputs, ledger, handler)
    client.bind_request_lifecycle_observer(_LocalRequestScope())
    try:
        envelope, slots = _planned_portfolio(client)
        preview = _preview(**inputs, logical_request_id=envelope.scheduler_logical_request_id)
        if failure == "pricing_drift":
            slots = (replace(slots[0], endpoint_pricing_snapshot_sha256="f" * 64),)
        elif failure == "underfunded":
            slots = (replace(slots[0], maximum_cost_usd=Decimal("0.001")),)
        portfolio = await client.budget.reserve_portfolio(envelope.envelope_sha256, slots)
        if failure == "unknown_after_hold":
            unrelated = ledger.reserve("synthetic-other-call", Decimal("0.01"))
            ledger.commit_for_transport(unrelated)
        before = ledger.snapshot()
        with pytest.raises((BudgetExhaustedError, BudgetReservationStateError, OpenRouterError)):
            async with client.budget.portfolio_task_scope(portfolio, slots[0].task_id):
                await _complete_reserved(client, preview)
        assert ledger.snapshot() == before and not usage.records
        await client.budget.release_portfolio(portfolio)
    finally:
        await client.close()
        await http_client.aclose()


@pytest.mark.asyncio
async def test_exact_held_portfolio_slot_is_consumed_by_actual_reservation_transport(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    """Invariant: a held slot is claimed only by its exact request, pricing and scope."""

    inputs = _reservation_inputs(config_factory, tmp_path)
    preview = _preview(**inputs)
    ledger = AtomicCostLedger.initialize(tmp_path / "held-slot-ledger.json", cap_usd=Decimal("250"))

    def handler(_request: httpx.Request) -> httpx.Response:
        snapshot = ledger.snapshot()
        assert snapshot.held_portfolio_usd == 0
        assert snapshot.entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    client, http_client, _usage = _client_for_inputs(inputs, ledger, handler)
    client.bind_request_lifecycle_observer(_LocalRequestScope())
    slot = _slot(preview)
    portfolio = await client.budget.reserve_portfolio("a" * 64, (slot,))
    assert ledger.snapshot().held_portfolio_usd == slot.maximum_cost_usd
    try:
        async with client.budget.portfolio_task_scope(portfolio, slot.task_id):
            result = await _complete_reserved(client, preview)
        await client.budget.release_portfolio(portfolio)
    finally:
        await client.close()
        await http_client.aclose()
    assert result.value.answer == "ok"
    assert ledger.snapshot().spent_usd == Decimal("0.01")
    assert len(operator_cost_attempts_from_usage(result.usage_record)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", (None, "ledger_entry_sha256", "ledger_reservation_id"))
async def test_recovered_actual_usage_must_match_each_durable_cost_entry(
    config_factory: Any,
    tmp_path: Path,
    tamper: str | None,
) -> None:
    """Invariant: replay restores counters, never substitutes or erases durable bills."""

    inputs = _reservation_inputs(config_factory, tmp_path, maximum_attempts=2)
    package = _empty_context_package(role="model_benchmark")
    preview = _context_preview(inputs, package, "synthetic-recovered-request")
    ledger = AtomicCostLedger.initialize(tmp_path / "recovery-ledger.json", cap_usd=Decimal("250"))

    def handler(_request: httpx.Request) -> httpx.Response:
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    client, http_client, _usage = _client_for_inputs(inputs, ledger, handler)
    client.bind_request_lifecycle_observer(_LocalRequestScope())
    try:
        result = await _complete_reserved(client, preview, context_package=package)
    finally:
        await client.close()
        await http_client.aclose()
    record = result.usage_record
    if tamper is not None:
        values = record.model_dump(mode="json")
        attempt = values["routing"]["operator_cost_attempts"][0]
        attempt[tamper] = "f" * (32 if tamper == "ledger_reservation_id" else 64)
        attempt["evidence_sha256"] = canonical_sha256(
            {key: value for key, value in attempt.items() if key != "evidence_sha256"}
        )
        values["routing"]["operator_cost_attempt_sha256s"] = [attempt["evidence_sha256"]]
        record = UsageRecord.model_validate_json(json.dumps(values))
    records = (record,)
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    resumed, resumed_http, _resumed_usage = _client_for_inputs(inputs, reopened, handler)
    resumed.bind_request_lifecycle_observer(_LocalRequestScope())
    before = reopened.snapshot()
    scope = _issue_trusted_budget_recovery_scope(records)
    try:
        if tamper is not None:
            with pytest.raises(BudgetReservationStateError, match="operator cost evidence differs"):
                await resumed.budget.restore_recovered_usage(records, recovery_scope=scope)
            assert resumed.budget.recovery_required
            assert reopened.snapshot() == before
        else:
            await resumed.budget.restore_recovered_usage(records, recovery_scope=scope)
            assert not resumed.budget.recovery_required
            assert resumed.budget.spent_usd_exact == Decimal("0.01")
            assert reopened.snapshot() == before
            later = _context_preview(inputs, package, "synthetic-after-recovery")
            assert (
                await _complete_reserved(resumed, later, context_package=package)
            ).value.answer == "ok"
            assert reopened.snapshot().spent_usd == Decimal("0.02")
    finally:
        await resumed.close()
        await resumed_http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("unknown_after_recovery", (False, True))
async def test_proven_presend_adoption_keeps_exact_reservation_and_rechecks_cost_stop(
    config_factory: Any,
    tmp_path: Path,
    unknown_after_recovery: bool,
) -> None:
    """Invariant: exact unsent adoption cannot waive a newly recorded unknown bill."""

    inputs = _reservation_inputs(config_factory, tmp_path)
    preview = _preview(**inputs)
    ledger = AtomicCostLedger.initialize(tmp_path / "adoption-ledger.json", cap_usd=Decimal("250"))
    pending = ledger.reserve(
        preview.logical_request_id, Decimal(preview.maximum_cost_usd_per_attempt_exact)
    )
    # Synthetic scheduler claim, confined to this disposable ledger; no REAL credit.
    attempt = SimpleNamespace(
        request_id=preview.logical_request_id,
        logical_request_id=preview.logical_request_id,
        task_id=preview.logical_request_id,
        requested_model=preview.exact_model_id,
        role=preview.role,
        status=SimpleNamespace(value="adopted_proven_pre_send"),
        reserved_cost_usd_exact=pending.reserved_usd,
        accounted_cost_usd_exact=Decimal(0),
        request_limit_scope=None,
        request_limit_count_before=None,
        request_limit_count_after=None,
        request_limit_maximum=None,
    )
    observed = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        entries = ledger.snapshot().entries
        assert len(entries) == 1 and entries[0].reservation_id == pending.reservation_id
        assert entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    client, http_client, usage = _client_for_inputs(inputs, reopened, handler)
    scope = _issue_trusted_budget_recovery_scope((), non_usage_attempts=(attempt,))
    await client.budget.restore_recovered_usage((), recovery_scope=scope)
    if unknown_after_recovery:
        other = ledger.reserve("unresolved-other-attempt", Decimal("1"))
        ledger.commit_for_transport(other)
    before = ledger.snapshot()
    try:
        if unknown_after_recovery:
            with pytest.raises((BudgetExhaustedError, OpenRouterError)):
                await _complete_reserved(client, preview)
            assert not observed and not usage.records
            assert ledger.snapshot() == before
            assert ledger.active_reservation(preview.logical_request_id) == pending
        else:
            result = await _complete_reserved(client, preview)
            assert result.value.answer == "ok" and len(observed) == 1
            entry = ledger.snapshot().entries[0]
            assert entry.reservation_id == pending.reservation_id
            assert entry.actual_cost_usd == Decimal("0.01")
            assert operator_cost_attempts_from_usage(result.usage_record)[
                0
            ].ledger_entry_sha256 == cost_entry_sha256(entry)
    finally:
        await client.close()
        await http_client.aclose()
