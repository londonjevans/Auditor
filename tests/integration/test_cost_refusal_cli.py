"""Local ledger-to-budget/CLI and real smoke-preflight refusal integration.

All route and lineage inputs are synthetic fixtures. No provider, secret, billed
observation, custody authority or qualification is supplied by these tests.
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import typer

import mmaudit.cli as cli_module
from mmaudit.config import AuditConfig
from mmaudit.constants import ExitCode
from mmaudit.orchestration.budgets import BudgetPriorBillingUnknownError
from mmaudit.orchestration.cost_ledger import CostEntryStatus, CostPriorBillingUnknownError
from tests.cli_support import IsolatedLoopCliRunner as CliRunner
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.integration.test_route_cost_reservation_ledger import _manager, _reserve
from tests.unit.test_authenticated_runner_smoke_cli import _required_arguments
from tests.unit.test_route_cost_reservations import _inputs
from tests.unit.test_smoke_cost_readiness import _launch


@pytest.mark.parametrize("preflight_only", (False, True))
def test_real_smoke_cli_refuses_unknown_billing_before_secret_selection(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
    forbid_network_and_secrets: list[str],
    preflight_only: bool,
) -> None:
    launch = _launch(tmp_path, config_factory, operator_role="all")
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    prior = ledger.reserve("synthetic-prior", Decimal("0.25"))
    ledger.commit_for_transport(prior)
    ledger.reconcile(prior, None)
    retained = ledger.path.read_bytes()

    # Substitute only the explicit synthetic input-loading boundary. The CLI
    # constructs its real launch; registry, policy and preflight checks stay real.
    monkeypatch.setattr(cli_module, "load_config", lambda _: launch.config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _: launch.benchmark_suite)
    monkeypatch.setattr(
        cli_module, "load_authenticated_runner_smoke_corpus_bundle", lambda _: launch.smoke_corpus
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_public_model_lineage",
        lambda: launch.public_lineage_capability,
    )
    registries = {
        "candidate-registry.json": launch.candidate_registry,
        "primary-judge-registry.json": launch.run_plans[0].judge_registry,
        "replay-judge-registry.json": launch.run_plans[1].judge_registry,
    }
    discovery = {
        "candidate-discovery": (
            launch.candidate_discovery_manifest,
            launch.candidate_discovery_evidence,
        ),
        "primary-judge-discovery": (
            launch.run_plans[0].judge_discovery_manifest,
            launch.run_plans[0].judge_discovery_evidence,
        ),
        "replay-judge-discovery": (
            launch.run_plans[1].judge_discovery_manifest,
            launch.run_plans[1].judge_discovery_evidence,
        ),
    }
    monkeypatch.setattr(cli_module, "load_candidate_registry", lambda path: registries[path.name])
    monkeypatch.setattr(cli_module, "load_model_discovery_run", lambda path: discovery[path.name])
    monkeypatch.setattr(
        cli_module, "_budget_and_usage", lambda *_args, **_kwargs: (launch.budget, launch.usage)
    )

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("cost refusal must precede secrets, execution and publication")

    for name in (
        "select_operator_secret_file",
        "load_operator_secrets",
        "execute_authenticated_runner_smoke_openrouter",
        "_write_authenticated_runner_smoke_output_fresh",
    ):
        monkeypatch.setattr(cli_module, name, forbidden)
    result = CliRunner().invoke(
        cli_module.app,
        _required_arguments(tmp_path, preflight_only=preflight_only, include_secret=False),
    )
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    output = " ".join(result.output.split())
    assert "mmaudit failed safely: UNKNOWN_PRIOR_BILLING:" in output
    assert "unknown billing blocks new work" in output
    assert "preflight: VALID" not in output
    assert "Traceback" not in output
    assert ledger.path.read_bytes() == retained
    assert launch.usage.records == []
    assert not (tmp_path / "smoke-evidence.json").exists()
    assert forbid_network_and_secrets == []


@pytest.mark.parametrize("pre_reserved", (False, True))
def test_real_budget_refusal_survives_cli_boundary_without_state_changes(
    tmp_path: Path,
    forbid_network_and_secrets: list[str],
    pre_reserved: bool,
) -> None:
    manager, ledger = _manager(tmp_path / "synthetic.json")
    assert ledger is not None
    observed: list[RuntimeError] = []
    retained: list[bytes] = []

    async def execute() -> None:
        pending = await _reserve(manager, _inputs()) if pre_reserved else None
        prior = ledger.reserve("synthetic-private-label-never-print", Decimal("0.25"))
        ledger.commit_for_transport(prior)
        ledger.reconcile(prior, None)
        retained.append(ledger.path.read_bytes())
        try:
            if pending is None:
                await _reserve(manager, _inputs())
            else:
                # Simulate billing becoming unknown after a successful reservation.
                await manager.commit_active_reservation_for_transport(pending)
        except (BudgetPriorBillingUnknownError, CostPriorBillingUnknownError) as exc:
            observed.append(exc)
            raise

    app = typer.Typer()

    @app.command()
    def check() -> None:
        cli_module._run_async_cli(execute)

    result = CliRunner().invoke(app, [])
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert len(observed) == 1
    assert type(observed[0]) is (
        CostPriorBillingUnknownError if pre_reserved else BudgetPriorBillingUnknownError
    )
    output = " ".join(result.output.split())
    assert "mmaudit failed safely: UNKNOWN_PRIOR_BILLING:" in output
    assert "exceeds the persistent model-cost budget" not in output
    assert "synthetic-private-label-never-print" not in output
    assert "Traceback" not in output
    assert ledger.path.read_bytes() == retained[0]
    assert len(ledger.snapshot().entries) == (2 if pre_reserved else 1)
    assert len(manager._issued) == (1 if pre_reserved else 0)
    assert (
        next(
            item
            for item in ledger.snapshot().entries
            if item.request_id.startswith("synthetic-private")
        ).status
        is CostEntryStatus.UNCERTAIN_ACCOUNTED
    )
    assert forbid_network_and_secrets == []
