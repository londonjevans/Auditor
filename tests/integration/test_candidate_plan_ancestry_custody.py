"""Local-only CLI custody checks; private test outputs are never adopted."""

from __future__ import annotations

import socket
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import FrameType
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
import mmaudit.models.candidate_plan_ancestry as ancestry_module
import mmaudit.orchestration.authenticated_runner_smoke_openrouter as smoke_runtime_module
import mmaudit.release_io as release_io_module
from mmaudit.config import AuditConfig
from mmaudit.constants import ExitCode
from mmaudit.models.candidate_plan_ancestry import VerifiedCandidateSelectionPlanAncestry
from mmaudit.models.candidate_registry_bridge import write_candidate_registry_json
from mmaudit.models.candidate_selection import (
    derive_pending_candidate_registry_from_selection_plan,
    load_candidate_selection_plan,
)
from mmaudit.models.discovery import ModelDiscoveryValidationError
from mmaudit.models.qualification import (
    load_candidate_registry,
    validate_candidate_registry_discovery,
)
from mmaudit.models.route_constraints import ExactRouteRole
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import OperatorSecrets
from tests.unit import test_authenticated_runner_smoke_runtime as smoke_fixtures
from tests.unit import test_candidate_benchmark as candidate_fixtures
from tests.unit.test_candidate_selection import _constrained_discovery

ROOT = Path(__file__).parents[2]
ACTIVE_PLAN = ROOT / "config" / "models.selection-plan.json"
REFRESH_ARGUMENTS = [
    "--refresh-endpoint-inventory",
    "--primary-judge-endpoint",
    "deepinfra/fp4",
    "--replay-judge-endpoint",
    "together",
]


@pytest.fixture(autouse=True)
def local_only(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Neither capability validation nor refusal may reach secrets or external execution."""

    before = ACTIVE_PLAN.read_bytes()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("ancestry integration must not use external execution or credentials")

    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli_module, "OpenRouterClient", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    yield
    assert ACTIVE_PLAN.read_bytes() == before


@pytest.mark.parametrize("case", ("normal", "multi_endpoint", "forged_instance", "mutated_class"))
def test_cli_preserves_exact_ancestry_custody_before_private_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    case: str,
) -> None:
    if case == "forged_instance":
        forged = object.__new__(VerifiedCandidateSelectionPlanAncestry)
        monkeypatch.setattr(
            cli_module, "resolve_verified_candidate_selection_plan_ancestry", lambda: forged
        )
    elif case == "mutated_class":
        monkeypatch.setattr(
            VerifiedCandidateSelectionPlanAncestry, "__eq__", lambda _self, _other: True
        )
    output = tmp_path / "private" / "non-authorizing-plan.json"
    candidate = (
        "google/gemini-3.7-flash=together"
        if case == "multi_endpoint"
        else "anthropic/claude-opus-5=amazon-bedrock"
    )
    result = CliRunner().invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-reactivation",
            "--candidate",
            candidate,
            "--output",
            str(output),
            "--no-color",
        ],
    )
    if case in {"normal", "multi_endpoint"}:
        assert result.exit_code == ExitCode.SUCCESS, result.output
        plan = load_candidate_selection_plan(output)
        assert plan.schema_version == "1.8"
        assert plan.ancestry_transition_binding is not None
        assert plan.ancestry_transition_binding.production_selection_authorized is False
        assert plan.ancestry_transition_binding.provider_call_authorized is False
        model_id, endpoint = candidate.split("=", 1)
        assert next(
            entry.allowed_provider_endpoints
            for entry in plan.entries
            if entry.exact_model_id == model_id
        ) == (endpoint,)
        assert output.stat().st_mode & 0o777 == 0o600
        assert "plan was not adopted" in " ".join(result.output.split())
    else:
        assert result.exit_code == ExitCode.CONFIGURATION, result.output
        assert not output.exists()
        expected = (
            "absent or fork-inherited" if case == "forged_instance" else "runtime boundary changed"
        )
        assert expected in " ".join(result.output.split())


@pytest.mark.parametrize(
    "failure", ("validation", "parent_rename", "parent_mode", "file_mode", "bytes")
)
@pytest.mark.parametrize("refresh", (False, True))
def test_cli_rolls_back_private_output_after_late_publication_failure(
    tmp_path: Path, failure: str, refresh: bool
) -> None:
    output = tmp_path / "private" / "nonauthorizing-plan.json"
    moved = tmp_path / "moved-private"
    triggered = False
    previous_profile = sys.getprofile()

    def inject_local_failure(frame: FrameType, event: str, _arg: object) -> None:
        nonlocal triggered
        if triggered or not output.exists():
            return
        if failure == "validation":
            if (
                event == "call"
                and frame.f_code.co_name == "validate_impl"
                and frame.f_globals is vars(ancestry_module)
            ):
                triggered = True
                raise ancestry_module.CandidateSelectionPlanAncestryError(
                    "synthetic final ancestry validation failure"
                )
        elif (
            event == "return"
            and frame.f_code is release_io_module._observe_file_twice.__code__
            and frame.f_locals.get("relative_path") == output.name
        ):
            triggered = True
            if failure == "parent_rename":
                output.parent.rename(moved)
                output.parent.mkdir(mode=0o700)
            elif failure == "parent_mode":
                output.parent.chmod(0o777)
            elif failure == "file_mode":
                output.chmod(0o644)
            else:
                output.write_bytes(b"synthetic late byte drift")

    try:
        sys.setprofile(inject_local_failure)
        result = CliRunner().invoke(
            cli_module.app,
            [
                "models",
                "emit-selection-plan-reactivation",
                "--candidate",
                (
                    "deepseek/deepseek-v4-pro-0813=together"
                    if refresh
                    else "anthropic/claude-opus-5=amazon-bedrock"
                ),
                *(REFRESH_ARGUMENTS if refresh else []),
                "--output",
                str(output),
                "--no-color",
            ],
        )
    finally:
        sys.setprofile(previous_profile)
    assert triggered
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert not output.exists()
    assert not (moved / output.name).exists()
    assert "plan was not adopted" not in result.output


@pytest.mark.parametrize(
    "candidate",
    (
        "moonshotai/kimi-k3=together",
        "deepseek/deepseek-v4-pro-0813=together",
        "z-ai/glm-5.2=deepinfra/fp4",
    ),
)
def test_legacy_reactivation_does_not_implicitly_refresh_operator_routes(
    tmp_path: Path,
    candidate: str,
) -> None:
    """The real pinned transition refuses unlisted endpoints before any output."""

    output = tmp_path / "unpublished" / "selection.json"
    result = CliRunner().invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-reactivation",
            "--candidate",
            candidate,
            "--output",
            str(output),
            "--no-color",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert "uses an unlisted endpoint" in " ".join(result.output.split())
    assert not output.parent.exists()
    assert "Published" not in result.output


@pytest.mark.parametrize(
    "case", ("normal", "missing_primary", "missing_replay", "implicit", "collision", "forged")
)
@pytest.mark.parametrize("reservation_costs", (False, True))
def test_explicit_three_role_cli_publication_is_private_and_nonauthorizing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, reservation_costs: bool
) -> None:
    output = tmp_path / "private" / "plan.json"
    arguments = list(REFRESH_ARGUMENTS)
    if case == "missing_primary":
        del arguments[1:3]
    elif case == "missing_replay":
        del arguments[3:5]
    elif case == "implicit":
        arguments.remove("--refresh-endpoint-inventory")
    elif case == "collision":
        output.parent.mkdir(mode=0o700)
        output.write_bytes(b"preexisting synthetic output must survive")
    elif case == "forged":
        monkeypatch.setattr(
            cli_module,
            "resolve_verified_candidate_selection_plan_ancestry",
            lambda: object.__new__(VerifiedCandidateSelectionPlanAncestry),
        )
    if reservation_costs:
        arguments.append("--reserve-then-reconcile-costs")
    result = CliRunner().invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-reactivation",
            "--candidate",
            "deepseek/deepseek-v4-pro-0813=together",
            *arguments,
            "--output",
            str(output),
            "--no-color",
        ],
    )
    if case == "normal":
        assert result.exit_code == ExitCode.SUCCESS, result.output
        plan = load_candidate_selection_plan(output)
        assert plan.schema_version == ("1.10" if reservation_costs else "1.9")
        if reservation_costs:
            assert plan.operator_cost_transition_binding is not None
            assert "no provider-enforced total ceiling" in " ".join(result.output.split())
        else:
            assert plan.ancestry_route_transition_binding is not None
        capability = ancestry_module.resolve_verified_candidate_selection_plan_ancestry()
        assert (
            ancestry_module.validate_candidate_selection_plan_reactivation(
                capability, successor=plan
            )
            == plan
        )
        assert output.stat().st_mode & 0o777 == 0o600
        normalized = " ".join(result.output.split())
        assert "staged and unverified" in normalized
        assert "plan was not adopted" in normalized
    else:
        assert result.exit_code == ExitCode.CONFIGURATION, result.output
        if case == "collision":
            assert output.read_bytes() == b"preexisting synthetic output must survive"
        else:
            assert not output.parent.exists()


@pytest.mark.parametrize("output_tokens", (4096, 2048))
@pytest.mark.parametrize("reservation_costs", (False, True))
def test_exact_cli_refresh_reaches_synthetic_constrained_registry_and_live_route_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    output_tokens: int,
    reservation_costs: bool,
    use_active_plan: bool = False,
) -> None:
    """Exercise real custody consumers using synthetic metadata, never retained REAL evidence."""

    tmp_path.chmod(0o700)
    output = tmp_path / "plan" / "nonauthorizing.json"
    emitted = CliRunner().invoke(
        cli_module.app,
        [
            "models",
            "emit-selection-plan-reactivation",
            "--candidate",
            "deepseek/deepseek-v4-pro-0813=together",
            *REFRESH_ARGUMENTS,
            *(["--reserve-then-reconcile-costs"] if reservation_costs else []),
            "--output",
            str(output),
            "--no-color",
        ],
    )
    assert emitted.exit_code == ExitCode.SUCCESS, emitted.output
    plan = load_candidate_selection_plan(output)
    if use_active_plan:
        from scripts.validate_governance_state import validate_current_selection_plan

        active_plan = load_candidate_selection_plan(ACTIVE_PLAN)
        # The unchanged explicit CLI still emits the original September-9 v1.10.
        # The adopted legacy allowance is its separately authenticated successor,
        # never an implicit extra policy change in that older command.
        assert reservation_costs and plan.schema_version == "1.10"
        assert active_plan.schema_version == "1.11"
        assert active_plan.predecessor_plan_sha256 == plan.plan_sha256
        validate_current_selection_plan(plan)
        validate_current_selection_plan(active_plan)
        plan = active_plan
    selection = plan.authenticated_runner_selection
    assert selection is not None
    config = smoke_fixtures._smoke_config(config_factory)
    config = AuditConfig.model_validate(
        {
            **config.model_dump(),
            "execution": {
                **config.execution.model_dump(),
                "max_output_tokens_per_request": output_tokens,
            },
        }
    )
    arguments = ["models", "authenticated-runner-smoke"]
    routes = {
        ExactRouteRole.CANDIDATE: "candidate",
        ExactRouteRole.PRIMARY_JUDGE: "primary-judge",
        ExactRouteRole.REPLAY_JUDGE: "replay-judge",
    }
    for constraint in selection.route_constraints:
        role_path = tmp_path / routes[constraint.role]
        manifest, evidence = _constrained_discovery(
            tmp_path=role_path,
            config=config,
            plan=plan,
            specs=(
                candidate_fixtures._CandidateSpec(
                    model_id=constraint.exact_model_id,
                    provider_endpoint=constraint.provider_endpoint,
                    provider_name=f"Synthetic {constraint.role.value} provider",
                    native_structured_output_parameter="structured_outputs",
                ),
            ),
        )
        registry = derive_pending_candidate_registry_from_selection_plan(
            plan=plan, run_manifest=manifest, evidence=evidence
        )
        registry_path = role_path / "registry.json"
        write_candidate_registry_json(registry_path, registry)
        loaded = load_candidate_registry(registry_path)
        validate_candidate_registry_discovery(
            registry=loaded, run_manifest=manifest, evidence=evidence
        )
        assert loaded.candidates[0].selection_plan_sha256 == plan.plan_sha256
        assert loaded.candidates[0].exact_route_constraint_sha256 == constraint.constraint_sha256
        assert loaded.candidates[0].approved_roles == ()
        arguments.extend(
            (
                f"--{routes[constraint.role]}-registry",
                str(registry_path),
                f"--{routes[constraint.role]}-discovery-run",
                str(role_path / "discovery-run"),
            )
        )
    config_path = tmp_path / "synthetic.toml"
    config_path.write_text("# typed synthetic config supplied in memory\n")
    secret_reference = tmp_path / "synthetic-secret-reference.txt"
    secret_reference.write_text("# no credentials: loader is trapped and replaced in memory\n")
    budget = candidate_fixtures._budget(tmp_path / "local-ledger", config)
    usage = UsageLedger()
    ledger = budget.atomic_ledger
    assert ledger is not None
    ledger_before = ledger.snapshot()
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "_budget_and_usage", lambda *_args, **_kwargs: (budget, usage))
    secret = OperatorSecrets({"OPENROUTER_API_KEY": "synthetic-local-only-plan-routes"})

    def synthetic_secrets(path: Path, *, required: bool) -> OperatorSecrets:
        assert path == secret_reference and required
        return secret

    monkeypatch.setattr(cli_module, "load_operator_secrets", synthetic_secrets)
    original = smoke_runtime_module.preflight_authenticated_runner_smoke_live_routes
    observed: list[candidate_fixtures._MockClientFactory] = []

    async def local_preflight(**kwargs: Any) -> Any:
        factory = smoke_fixtures._install_live_route_client_factory(
            monkeypatch,
            kwargs["launch"],
            canonical_shape_models={item.exact_model_id for item in selection.route_constraints},
        )
        observed.append(factory)
        return await original(**kwargs)

    async def forbidden_completion(**_kwargs: object) -> None:
        raise AssertionError("route refresh preflight must not dispatch any completion")

    monkeypatch.setattr(
        cli_module, "preflight_authenticated_runner_smoke_live_routes", local_preflight
    )
    monkeypatch.setattr(
        cli_module, "execute_authenticated_runner_smoke_openrouter", forbidden_completion
    )
    smoke_output = tmp_path / "unpublished-smoke.json"
    arguments.extend(
        (
            "--smoke-corpus",
            str(ROOT / "benchmarks/model_corpus_smoke"),
            "--smoke-run-index",
            "1",
            "--output",
            str(smoke_output),
            "--candidate-cost-cap-usd-per-attempt",
            "1.00",
            "--primary-judge-cost-cap-usd-per-attempt",
            "1.00",
            "--replay-judge-cost-cap-usd-per-attempt",
            "1.00",
            "--config",
            str(config_path),
            "--corpus",
            str(ROOT / "benchmarks/model_corpus/manifest.json"),
            "--cost-ledger",
            str(ledger.path),
            "--secrets-env-file",
            str(secret_reference),
            "--allow-metadata-egress",
            "--live-route-preflight-only",
            "--no-color",
        )
    )
    result = CliRunner().invoke(cli_module.app, arguments)
    if output_tokens == 2048:
        assert result.exit_code == ExitCode.CONFIGURATION, result.output
        assert "RUNTIME_OUTPUT_TOKENS_MISMATCH" in result.output
    else:
        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert len(observed[0].clients) == 3
        assert "NO MODEL COMPLETION" in " ".join(result.output.split())
    assert len(observed) == 1
    assert observed[0].request_bodies == []
    assert usage.records == []
    assert ledger.snapshot() == ledger_before
    assert not smoke_output.exists()
    assert secret.cleared is True
    assert "synthetic-local-only-plan-routes" not in result.output


@pytest.mark.parametrize("output_tokens", (4096, 2048))
def test_active_cost_plan_reaches_registry_and_enforces_runtime_output_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    output_tokens: int,
) -> None:
    """The actual active plan reaches all three local routes without changing the token gate."""

    test_exact_cli_refresh_reaches_synthetic_constrained_registry_and_live_route_preflight(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        config_factory=config_factory,
        output_tokens=output_tokens,
        reservation_costs=True,
        use_active_plan=True,
    )


@pytest.mark.parametrize("role", tuple(ExactRouteRole))
def test_active_cost_successor_refuses_each_predecessor_bound_discovery(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    role: ExactRouteRole,
) -> None:
    """Invariant: old constrained discovery cannot be relabeled for the adopted cost plan."""

    predecessor = load_candidate_selection_plan(
        ROOT / "tests/fixtures/model_selection/provider-ceiling-plan-v1.9.json"
    )
    current = load_candidate_selection_plan(ACTIVE_PLAN)
    selection = predecessor.authenticated_runner_selection
    assert selection is not None
    (constraint,) = tuple(item for item in selection.route_constraints if item.role is role)
    manifest, evidence = _constrained_discovery(
        tmp_path=tmp_path,
        config=smoke_fixtures._smoke_config(config_factory),
        plan=predecessor,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=constraint.exact_model_id,
                provider_endpoint=constraint.provider_endpoint,
                provider_name=f"Synthetic stale {role.value} provider",
                native_structured_output_parameter="structured_outputs",
            ),
        ),
    )
    original = derive_pending_candidate_registry_from_selection_plan(
        plan=predecessor, run_manifest=manifest, evidence=evidence
    )
    assert original.candidates[0].selection_plan_sha256 == predecessor.plan_sha256
    assert current.plan_sha256 != predecessor.plan_sha256
    with pytest.raises(
        ModelDiscoveryValidationError,
        match="constrained discovery publication differs from its selected-plan custody",
    ):
        derive_pending_candidate_registry_from_selection_plan(
            plan=current, run_manifest=manifest, evidence=evidence
        )
