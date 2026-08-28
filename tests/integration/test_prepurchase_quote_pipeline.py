from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mmaudit.models.openrouter import OpenRouterClient
from mmaudit.models.prepurchase_quote import (
    AcceptedPrepurchaseQuote,
    PrepurchaseQuote,
)
from mmaudit.models.runtime import build_openrouter_runtime_controls
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager, BudgetReservationStateError
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.orchestration.prepurchase_quote import (
    PrepurchaseQuotePlanningError,
    validate_accepted_prepurchase_quote_for_run,
)
from tests.fake_openrouter import FakeOpenRouter
from tests.integration.test_coverage_pipeline_integration import _compact_solidity_config
from tests.integration.test_pipeline import StaticScannerRunner, _foundry_repo
from tests.unit.test_prepurchase_quote import _quote_fixture


def _quoted_mock_client(
    config: Any,
    fake: FakeOpenRouter,
    *,
    acceptance: AcceptedPrepurchaseQuote,
    ledger: Any,
    quoted_budget: bool,
) -> OpenRouterClient:
    controls = build_openrouter_runtime_controls(config, certification=False)
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        per_model_usd_caps={
            model: str(cap) for model, cap in config.token_budgets.per_model_cost_budget_usd.items()
        },
        per_role_usd_caps={
            role: str(cap) for role, cap in config.token_budgets.per_role_cost_budget_usd.items()
        },
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
        accepted_quote=acceptance if quoted_budget else None,
    )
    return OpenRouterClient(
        api_key="synthetic-quote-pipeline-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=UsageLedger(),
        base_url="https://fake.openrouter.test",
        provider_policy=controls.provider_policy,
        reasoning_policy=None,
        token_budgets=config.token_budgets,
        test_only_mock_handler=fake.handler,
    )


def _fixture_acceptance_and_ledger(
    tmp_path: Path,
    config_factory: Callable[..., Any],
    *,
    seed: str,
) -> tuple[AcceptedPrepurchaseQuote, Any]:
    fixture = _quote_fixture(tmp_path, config_factory, seed=seed, cap_usd="20")
    return fixture.acceptance, fixture.ledger


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
@pytest.mark.parametrize("ci_mode", [False, True])  # type: ignore[untyped-decorator]
async def test_scanner_and_ci_reject_accepted_quote_before_output(
    config_factory: Callable[..., Any],
    vulnerable_repo: Path,
    tmp_path: Path,
    ci_mode: bool,
) -> None:
    acceptance, _ledger = _fixture_acceptance_and_ledger(
        tmp_path,
        config_factory,
        seed=f"scanner-ci-rejection-{ci_mode}",
    )
    output = tmp_path / f"scanner-ci-output-{ci_mode}"
    pipeline = AuditPipeline(
        config_factory(),
        repo=vulnerable_repo,
        output=output,
        accepted_prepurchase_quote=acceptance,
    )

    with pytest.raises(
        ValueError,
        match="accepted pre-purchase quotes are unavailable for scanner-only runs",
    ):
        await pipeline.run(scanner_only=True, ci_mode=ci_mode)

    assert not (output / "runs").exists()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_injected_budget_must_bind_the_same_accepted_quote_before_reservation(
    config_factory: Callable[..., Any],
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = config_factory(privacy={"fail_on_detected_secret": False}).effective()
    acceptance, ledger = _fixture_acceptance_and_ledger(
        tmp_path,
        config_factory,
        seed="injected-budget-parity",
    )
    fake = FakeOpenRouter()
    client = _quoted_mock_client(
        config,
        fake,
        acceptance=acceptance,
        ledger=ledger,
        quoted_budget=False,
    )
    pipeline = AuditPipeline(
        config,
        repo=vulnerable_repo,
        output=tmp_path / "injected-budget-parity-output",
        client=client,
        cost_ledger=ledger,
        scanner_runner=StaticScannerRunner(emit_finding=False),
        accepted_prepurchase_quote=acceptance,
    )

    try:
        with pytest.raises(
            ValueError,
            match="provider budget differs from the pipeline pre-purchase quote acceptance",
        ):
            await pipeline.run(allow_code_egress=True)
    finally:
        await client.close()

    snapshot = ledger.snapshot()
    assert fake.requests == []
    assert snapshot.entries == ()
    assert snapshot.portfolio_holds == ()


@pytest.mark.asyncio  # type: ignore[untyped-decorator]
async def test_quote_route_binding_survives_validator_bypass_before_paid_dispatch(
    config_factory: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _compact_solidity_config(config_factory)
    repository = _foundry_repo(tmp_path, patched=True)
    acceptance, ledger = _fixture_acceptance_and_ledger(
        tmp_path,
        config_factory,
        seed="validation-before-reservation",
    )
    fake = FakeOpenRouter(mode="clean_no_candidates")
    client = _quoted_mock_client(
        config,
        fake,
        acceptance=acceptance,
        ledger=ledger,
        quoted_budget=True,
    )
    observed = {"validation_calls": 0}

    def validate_before_paid_work(
        observed_config: Any,
        *,
        acceptance: AcceptedPrepurchaseQuote,
        campaign_manifest: Any,
        solidity_shard_inventory: Any,
        portfolio_preflight: Any,
        selected_model_ids: frozenset[str] | None,
    ) -> PrepurchaseQuote:
        assert observed_config is config
        assert acceptance == pipeline.accepted_prepurchase_quote
        assert fake.requests == []
        assert client.budget.reserved_usd == 0.0
        assert selected_model_ids is None
        snapshot = ledger.snapshot()
        assert snapshot.entries == ()
        assert snapshot.portfolio_holds == ()
        with pytest.raises(PrepurchaseQuotePlanningError, match="accepted quote"):
            validate_accepted_prepurchase_quote_for_run(
                observed_config,
                acceptance=acceptance,
                campaign_manifest=campaign_manifest,
                solidity_shard_inventory=solidity_shard_inventory,
                portfolio_preflight=portfolio_preflight,
            )
        observed["validation_calls"] += 1
        return acceptance.quote

    monkeypatch.setattr(
        "mmaudit.orchestration.pipeline.validate_accepted_prepurchase_quote_for_run",
        validate_before_paid_work,
    )

    pipeline = AuditPipeline(
        config,
        repo=repository,
        output=tmp_path / "accepted-quote-output",
        client=client,
        cost_ledger=ledger,
        scanner_runner=StaticScannerRunner(emit_finding=False),
        accepted_prepurchase_quote=acceptance,
    )

    try:
        with pytest.raises(
            BudgetReservationStateError,
            match="differs from every accepted quote route ceiling",
        ):
            await pipeline.run(allow_code_egress=True)
    finally:
        await client.close()

    assert observed["validation_calls"] == 1
    assert fake.requests == []
    snapshot = ledger.snapshot()
    assert snapshot.entries == ()
    assert snapshot.portfolio_holds == ()
