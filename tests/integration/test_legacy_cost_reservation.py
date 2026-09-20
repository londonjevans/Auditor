"""Original operator-cost consumers with exact synthetic history and sealed local transport."""

from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from mmaudit.models.openrouter import OpenRouterError
from mmaudit.models.route_constraints import RouteCostReservationPolicy
from mmaudit.models.route_cost_reservations import operator_cost_attempts_from_usage
from mmaudit.orchestration import authenticated_runner_smoke_openrouter as smoke_runtime
from mmaudit.orchestration.budgets import BudgetExhaustedError, _issue_trusted_budget_recovery_scope
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntryStatus,
    CostPriorBillingUnknownError,
)
from mmaudit.orchestration.scheduler_runtime import build_scheduler_cost_ledger_baseline
from tests.integration.test_operator_reservation_transport import (
    _client_for_inputs,
    _complete_reserved,
    _LocalRequestScope,
    _slot,
)
from tests.integration.test_operator_reservation_transport import (
    local_only as local_only,
)
from tests.legacy_cost_support import seed_legacy_uncertainty
from tests.unit.test_openrouter import _completion_response
from tests.unit.test_openrouter_operator_reservations import _reservation_inputs
from tests.unit.test_openrouter_request_cost_preview import _preview
from tests.unit.test_smoke_cost_readiness import _launch


def test_legacy_plan_round_trips_through_original_atomic_writer_and_fresh_ancestry(
    tmp_path: Path,
) -> None:
    from mmaudit.models.candidate_plan_ancestry import (
        resolve_verified_candidate_selection_plan_ancestry,
        validate_candidate_selection_plan_reactivation,
        write_candidate_selection_plan_reactivation,
    )
    from mmaudit.models.candidate_selection import load_candidate_selection_plan
    from tests.unit.test_candidate_plan_legacy_cost import _legacy_plan

    successor = _legacy_plan()
    path = tmp_path / "cost-only-plan.json"
    assert (
        write_candidate_selection_plan_reactivation(
            resolve_verified_candidate_selection_plan_ancestry(), path=path, successor=successor
        )
        == successor
    )
    assert path.stat().st_mode & 0o777 == 0o600
    observed = load_candidate_selection_plan(path)
    assert (
        validate_candidate_selection_plan_reactivation(
            resolve_verified_candidate_selection_plan_ancestry(), successor=observed
        )
        == successor
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("ordinary", "portfolio", "adoption"))
@pytest.mark.parametrize("other_unknown", (False, True))
async def test_real_cost_consumers_apply_only_exact_legacy_rows_and_recheck_new_uncertainty(
    config_factory: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    other_unknown: bool,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    allowance = seed_legacy_uncertainty(ledger, monkeypatch)
    original = ledger.snapshot().entries
    baseline = build_scheduler_cost_ledger_baseline(ledger)
    policy = RouteCostReservationPolicy.build(legacy_uncertain_allowance=allowance)
    inputs = _reservation_inputs(config_factory, tmp_path, operator_policy=policy)
    preview = _preview(**inputs)
    assert preview.operator_cost_reservation.policy == policy
    observed = []
    pending = None
    if mode == "adoption":
        pending = ledger.reserve(
            preview.logical_request_id, Decimal(preview.maximum_cost_usd_per_attempt_exact)
        )

    def handle(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        entry = next(
            item
            for item in ledger.snapshot().entries
            if item.request_id == preview.logical_request_id
        )
        assert entry.status is CostEntryStatus.UNCERTAIN_ACCOUNTED
        assert entry.actual_cost_usd is None and entry.accounted_cost_usd == entry.reserved_usd
        if pending is not None:
            assert entry.reservation_id == pending.reservation_id
        return _completion_response(
            '{"answer":"ok"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250"))
    client, http_client, usage = _client_for_inputs(inputs, reopened, handle)
    portfolio = None
    try:
        attempts = ()
        if mode == "adoption":
            assert pending is not None
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
            attempts = (attempt,)
        scope = _issue_trusted_budget_recovery_scope(
            (), non_usage_attempts=attempts, cost_ledger_baseline=baseline
        )
        await client.budget.restore_recovered_usage((), recovery_scope=scope)
        if mode == "portfolio":
            client.bind_request_lifecycle_observer(_LocalRequestScope())
            slot = _slot(preview)
            portfolio = await client.budget.reserve_portfolio("a" * 64, (slot,))
        if other_unknown:
            other = ledger.reserve("future-unlisted-attempt", Decimal("0.01"))
            ledger.commit_for_transport(other)
        before = ledger.path.read_bytes()

        async def complete() -> Any:
            if portfolio is not None:
                async with client.budget.portfolio_task_scope(portfolio, slot.task_id):
                    return await _complete_reserved(client, preview)
            return await _complete_reserved(client, preview)

        if other_unknown:
            with pytest.raises((BudgetExhaustedError, OpenRouterError)):
                await complete()
            assert not observed and not usage.records
            assert ledger.path.read_bytes() == before
        else:
            result = await complete()
            assert result.value.answer == "ok" and len(observed) == 1
            assert len(operator_cost_attempts_from_usage(result.usage_record)) == 1
            assert ledger.snapshot().spent_usd == Decimal("0.24330616")
        by_id = {entry.request_id: entry for entry in ledger.snapshot().entries}
        assert tuple(by_id[entry.request_id] for entry in original) == original
    finally:
        if portfolio is not None:
            await client.budget.release_portfolio(portfolio)
        await client.close()
        await http_client.aclose()


@pytest.mark.parametrize("strict_role", (None, "candidate", "primary", "replay"))
def test_every_smoke_role_requires_the_same_exact_historical_exception_without_calls(
    config_factory: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, strict_role: str | None
) -> None:
    # Create the exact policy on a disposable ledger, then use the launch's own original ledger.
    seed_path = tmp_path / "seed"
    seed_path.mkdir(mode=0o700)
    seed = AtomicCostLedger.initialize(seed_path / "synthetic.json", cap_usd=Decimal("250"))
    allowance = seed_legacy_uncertainty(seed, monkeypatch)
    policy = RouteCostReservationPolicy.build(legacy_uncertain_allowance=allowance)
    allowed_path = tmp_path / "allowed"
    strict_path = tmp_path / "strict"
    allowed_path.mkdir()
    strict_path.mkdir()
    launch = _launch(allowed_path, config_factory, operator_role="all", operator_policy=policy)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    # Copy only this test-created synthetic ledger state; never bind a reported live row.
    ledger.path.write_bytes(seed.path.read_bytes())
    if strict_role is not None:
        strict = _launch(strict_path, config_factory, operator_role="all")
        if strict_role == "candidate":
            launch = replace(
                launch,
                candidate_discovery_manifest=strict.candidate_discovery_manifest,
                candidate_discovery_evidence=strict.candidate_discovery_evidence,
                candidate_registry=strict.candidate_registry,
            )
        else:
            plans = list(launch.run_plans)
            index = 0 if strict_role == "primary" else 1
            plans[index] = strict.run_plans[index]
            launch = replace(launch, run_plans=tuple(plans))
    before = ledger.path.read_bytes()

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("preflight must never create a provider client")

    monkeypatch.setattr(smoke_runtime, "OpenRouterClient", forbidden)
    if strict_role is None:
        assert smoke_runtime.preflight_authenticated_runner_smoke_openrouter_launch(launch)
    else:
        with pytest.raises(CostPriorBillingUnknownError):
            smoke_runtime.preflight_authenticated_runner_smoke_openrouter_launch(launch)
    assert ledger.path.read_bytes() == before and not launch.usage.records
