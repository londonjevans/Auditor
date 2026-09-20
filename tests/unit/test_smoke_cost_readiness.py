"""Smoke launch readiness checks billing policy without mutating its ledger."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

import mmaudit.orchestration.authenticated_runner_smoke_openrouter as smoke_runtime
from mmaudit.config import AuditConfig
from mmaudit.models.route_constraints import RoutePredicateProfile
from mmaudit.models.route_cost_reservations import RouteCostReservationPolicy
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.orchestration.cost_ledger import CostPriorBillingUnknownError, ReleaseReason
from tests.unit import test_authenticated_runner_smoke_runtime as fixtures


def _launch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    *,
    operator_role: str,
    operator_policy: RouteCostReservationPolicy | None = None,
) -> smoke_runtime.AuthenticatedRunnerSmokeOpenRouterLaunch:
    config = fixtures._smoke_config(config_factory)
    reasoning = build_reasoning_policy(config)
    role = reasoning.role_policy_for_request("model_benchmark")
    profile = RoutePredicateProfile.build(
        reasoning_policy_sha256=reasoning.artifact_sha256,
        reasoning_role_profile_sha256=reasoning.role_profile.profile_sha256,
        reasoning_role_binding_sha256=role.binding_sha256,
        reasoning_control_profile_sha256=role.control.profile_sha256,
        reserved_reasoning_tokens=4096,
        minimum_prompt_tokens=65536,
        required_output_tokens=4096,
        minimum_context_tokens=73728,
        operator_reservation_policy=operator_policy or RouteCostReservationPolicy.build(),
    )
    operator_path = tmp_path / "operator"
    legacy_path = tmp_path / "legacy"
    operator_path.mkdir()
    legacy_path.mkdir()
    operator = fixtures._launch(
        config=config, tmp_path=operator_path, route_predicate_profile=profile
    )
    legacy = fixtures._launch(config=config, tmp_path=legacy_path)
    if operator_role == "all":
        return operator
    if operator_role == "none":
        return legacy
    if operator_role == "candidate":
        return replace(operator, run_plans=legacy.run_plans)
    index = 0 if operator_role == "primary" else 1
    plans = list(legacy.run_plans)
    plans[index] = operator.run_plans[index]
    return replace(legacy, run_plans=tuple(plans))


@pytest.mark.parametrize("operator_role", ("all", "candidate", "primary", "replay", "none"))
def test_unknown_history_stops_each_operator_launch_role_but_not_legacy_or_metadata(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
    operator_role: str,
) -> None:
    launch = _launch(tmp_path, config_factory, operator_role=operator_role)
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    prior = ledger.reserve("synthetic-prior", Decimal("0.25"))
    ledger.commit_for_transport(prior)
    ledger.reconcile(prior, None)
    retained = ledger.path.read_bytes()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError(
            "unknown-billing stop must precede request derivation or provider setup"
        )

    monkeypatch.setattr(smoke_runtime, "OpenRouterClient", forbidden)
    if operator_role != "none":
        with monkeypatch.context() as patch:
            patch.setattr(smoke_runtime, "_candidate_cost_plan", forbidden)
            with pytest.raises(CostPriorBillingUnknownError, match=r"^UNKNOWN_PRIOR_BILLING:"):
                smoke_runtime.preflight_authenticated_runner_smoke_openrouter_launch(launch)
    else:
        assert smoke_runtime.preflight_authenticated_runner_smoke_openrouter_launch(launch)
    # This mode admits only metadata inspection, never benchmark-code/provider execution.
    assert smoke_runtime.preflight_authenticated_runner_smoke_live_route_launch(
        replace(launch, explicitly_allow_synthetic_egress=False)
    )
    assert ledger.path.read_bytes() == retained
    assert launch.usage.records == []


@pytest.mark.parametrize("history", ("empty", "known-zero", "known-positive", "released"))
def test_operator_preflight_accepts_known_or_never_dispatched_history_without_writes(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    history: str,
) -> None:
    launch = _launch(tmp_path, config_factory, operator_role="all")
    ledger = launch.budget.atomic_ledger
    assert ledger is not None
    if history != "empty":
        prior = ledger.reserve("synthetic-prior", Decimal("0.25"))
        if history == "released":
            ledger.release(prior, reason=ReleaseReason.CANCELLED_BEFORE_SEND)
        else:
            ledger.commit_for_transport(prior)
            ledger.reconcile(prior, Decimal("0" if history == "known-zero" else "0.01"))
    retained = ledger.path.read_bytes()
    assert smoke_runtime.preflight_authenticated_runner_smoke_openrouter_launch(launch)
    assert ledger.path.read_bytes() == retained
    assert launch.usage.records == []
