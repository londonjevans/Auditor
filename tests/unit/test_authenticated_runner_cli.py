from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import typer
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.config import AuditConfig, ConfigError
from mmaudit.constants import ExitCode
from mmaudit.models.authenticated_runner import AuthenticatedCrossLineageRunnerEvidence
from mmaudit.models.authenticated_runner_durable_bundle import (
    AuthenticatedRunnerDurableBundleError,
    AuthenticatedRunnerDurableEvidenceBundle,
    authenticated_runner_durable_bundle_bytes,
)
from mmaudit.models.authenticated_runner_execution import (
    AuthenticatedRunnerExecutionError,
)
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealCollisionMap,
    EvidenceSealDecisionProjection,
)
from mmaudit.models.route_constraints import (
    RouteConstraintPurpose,
    RoutePredicateDisposition,
    RoutePredicateId,
    RoutePredicateReason,
    RoutePredicateRequirementError,
    RoutePredicateResult,
)
from mmaudit.orchestration.authenticated_runner_openrouter import (
    AuthenticatedRunnerOpenRouterExecutionSnapshot,
    AuthenticatedRunnerOpenRouterLaunch,
    AuthenticatedRunnerOpenRouterResult,
    AuthenticatedRunnerOpenRouterRunSnapshot,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.unit.test_authenticated_runner_durable_bundle import _rejected_bundle

RUNNER = CliRunner()


class _SecretPresenceOnly:
    """Context holder with no credential value or credential-value property."""

    openrouter_api_key_present = True

    def __enter__(self) -> _SecretPresenceOnly:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def _required_arguments(
    tmp_path: Path,
    *,
    allow_egress: bool = True,
    include_secret_file: bool = True,
    preflight_only: bool = False,
    include_runtime_evidence: bool = False,
    include_retry_continuity: bool = False,
) -> list[str]:
    arguments = [
        "models",
        "authenticated-runner",
        "--candidate-registry",
        str(tmp_path / "candidate-registry.json"),
        "--candidate-discovery-run",
        str(tmp_path / "candidate-discovery"),
        "--primary-judge-registry",
        str(tmp_path / "primary-judge-registry.json"),
        "--primary-judge-discovery-run",
        str(tmp_path / "primary-judge-discovery"),
        "--replay-judge-registry",
        str(tmp_path / "replay-judge-registry.json"),
        "--replay-judge-discovery-run",
        str(tmp_path / "replay-judge-discovery"),
        "--qualification-policy",
        str(tmp_path / "qualification-policy.json"),
        "--primary-campaign-journal",
        str(tmp_path / "primary-campaign"),
        "--primary-portfolio",
        str(tmp_path / "primary-portfolio"),
        "--replay-campaign-journal",
        str(tmp_path / "replay-campaign"),
        "--replay-portfolio",
        str(tmp_path / "replay-portfolio"),
        "--output",
        str(tmp_path / "runner-evidence.json"),
        "--candidate-cost-cap-usd-per-attempt",
        "0.01",
        "--primary-judge-cost-cap-usd-per-attempt",
        "0.02",
        "--replay-judge-cost-cap-usd-per-attempt",
        "0.03",
        "--config",
        str(tmp_path / "mmaudit.toml"),
        "--corpus",
        str(tmp_path / "manifest.json"),
        "--ground-truth-provenance",
        str(tmp_path / "provenance.json"),
        "--cost-ledger",
        str(tmp_path / "cost-ledger.json"),
    ]
    if include_secret_file:
        arguments.extend(("--secrets-env-file", str(tmp_path / "operator-secrets.env")))
    if include_runtime_evidence:
        arguments.extend(
            (
                "--runtime-evidence-smoke-bundle",
                str(tmp_path / "runtime-smoke-evidence.json"),
            )
        )
    if include_retry_continuity:
        arguments.extend(
            (
                "--retry-continuity-config",
                str(tmp_path / "retry-continuity.toml"),
            )
        )
    arguments.append("--no-color")
    if allow_egress:
        arguments.append("--allow-code-egress")
    if preflight_only:
        arguments.append("--preflight-only")
    return arguments


def _result() -> AuthenticatedRunnerOpenRouterResult:
    evidence = AuthenticatedCrossLineageRunnerEvidence.model_construct(
        evidence_sha256="a" * 64,
        serialized_authority=False,
        runner_custody_authorized=False,
    )
    collision_map = EvidenceSealCollisionMap.model_construct(collision_map_sha256="b" * 64)
    projections = tuple(
        EvidenceSealDecisionProjection.model_construct(
            projection_sha256=digest,
            model_qualification_authorized=False,
            production_selection_authorized=False,
        )
        for digest in ("c" * 64, "d" * 64)
    )
    runs = tuple(
        AuthenticatedRunnerOpenRouterRunSnapshot(
            candidate_cost_plan=cast(Any, f"candidate-cost-plan-{index}"),
            judge_cost_plan=cast(Any, f"judge-cost-plan-{index}"),
            candidate_report=cast(Any, f"candidate-report-{index}"),
            prepared_adjudication=cast(Any, f"prepared-{index}"),
            adjudication_report=cast(Any, f"adjudication-report-{index}"),
        )
        for index in range(2)
    )
    execution = AuthenticatedRunnerOpenRouterExecutionSnapshot(
        inventory=cast(
            Any,
            SimpleNamespace(effective_config_sha256="e" * 64),
        ),
        runs=runs,
    )
    return AuthenticatedRunnerOpenRouterResult(
        execution=execution,
        runner_evidence=evidence,
        authseal_collision_map=collision_map,
        authseal_decision_projections=projections,
        authseal_rejection_kind=None,
    )


def _durable_bundle() -> AuthenticatedRunnerDurableEvidenceBundle:
    return AuthenticatedRunnerDurableEvidenceBundle.model_construct(
        schema_version="1.2",
        effective_config_sha256="e" * 64,
        runner_evidence_sha256="f" * 64,
        closed_ledger_evidence=SimpleNamespace(
            entries=(object(), object()),
            final_spent_usd="0.125",
        ),
        authseal_comparison=SimpleNamespace(status="REJECTED"),
        serialized_authority=False,
        provider_call_authorized=False,
        source_egress_authorized=False,
        runner_custody_authorized=False,
        authority_issuance_authorized=False,
        benchmark_authorized=False,
        model_qualification_authorized=False,
        production_selection_authorized=False,
        seal_publication_authorized=False,
        release_authorized=False,
        bundle_sha256="e" * 64,
    )


def _legacy_durable_bundle() -> AuthenticatedRunnerDurableEvidenceBundle:
    return _durable_bundle().model_copy(update={"schema_version": "1.0"})


def _verification_config() -> object:
    return SimpleNamespace(
        stable_hash=lambda: "e" * 64,
        execution=SimpleNamespace(
            model_dump=lambda **_kwargs: {"synthetic": "execution-config"},
            max_model_retries=1,
            max_schema_validation_retries=3,
            maximum_model_attempts=5,
        ),
    )


def test_verify_authenticated_runner_help_exposes_offline_bundle_input() -> None:
    result = RUNNER.invoke(
        cli_module.app,
        ["models", "verify-authenticated-runner", "--help"],
        env={"COLUMNS": "120"},
    )

    assert result.exit_code == 0
    assert "--bundle" in result.stdout
    assert "--config" in result.stdout
    assert "--retry-continuity-config" in result.stdout
    assert "nonauthorizing" in result.stdout.lower()


def test_verify_authenticated_runner_is_offline_and_nonauthorizing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _durable_bundle()
    observed: list[Path] = []
    binding: dict[str, object] = {}

    def load(path: Path) -> AuthenticatedRunnerDurableEvidenceBundle:
        observed.append(path)
        return bundle

    def external_state_forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline verification must not access external state")

    monkeypatch.setattr(cli_module, "load_authenticated_runner_durable_bundle", load)
    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_default_config",
        lambda path: observed.append(path) or _verification_config(),
    )
    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_durable_config_binding",
        lambda supplied, **kwargs: binding.update(kwargs) or supplied,
    )
    for name in ("load_config", "load_operator_secrets", "_budget_and_usage"):
        monkeypatch.setattr(cli_module, name, external_state_forbidden)

    path = tmp_path / "runner-evidence.json"
    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner",
            "--bundle",
            str(path),
            "--config",
            str(tmp_path / "default.toml"),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert observed == [tmp_path / "default.toml", path]
    assert binding["effective_config_sha256"] == "e" * 64
    assert binding["maximum_attempts_per_logical_request"] == 5
    assert binding["model_retry_policy_sha256"] == (
        cli_module.ModelRetryPolicy.build(
            transient_retry_limit=1,
            schema_validation_retry_limit=3,
        ).policy_sha256
    )
    assert "VALID / NONAUTHORIZING" in result.stdout
    assert f"Bundle SHA-256: {bundle.bundle_sha256}" in result.stdout
    assert f"Runner SHA-256: {bundle.runner_evidence_sha256}" in result.stdout
    assert "entries=2; final_spent_usd=0.125" in result.stdout
    assert "AUTHSEAL comparison: REJECTED" in result.stdout


def test_verify_authenticated_runner_rejects_legacy_v10_without_calling_it_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _legacy_durable_bundle()
    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_default_config",
        lambda _path: _verification_config(),
    )
    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_durable_bundle",
        lambda _path: bundle,
    )
    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_durable_config_binding",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AuthenticatedRunnerDurableBundleError(
                "durable AUTHRUNNER evidence is legacy and lacks effective config custody"
            )
        ),
    )

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner",
            "--bundle",
            str(tmp_path / "legacy-v10.json"),
            "--config",
            str(tmp_path / "default.toml"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "legacy" in result.stdout.lower()
    assert "lacks effective config custody" in " ".join(result.stdout.split())
    assert "VALID / NONAUTHORIZING" not in result.stdout


def test_verify_authenticated_runner_replays_real_private_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _rejected_bundle()
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    path = parent / "runner-evidence.json"
    path.write_bytes(authenticated_runner_durable_bundle_bytes(bundle))
    path.chmod(0o600)
    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_default_config",
        lambda _path: _verification_config(),
    )
    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_durable_config_binding",
        lambda supplied, **_kwargs: supplied,
    )

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner",
            "--bundle",
            str(path),
            "--config",
            str(tmp_path / "default.toml"),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert f"Bundle SHA-256: {bundle.bundle_sha256}" in result.stdout
    assert f"Runner SHA-256: {bundle.runner_evidence_sha256}" in result.stdout
    assert "AUTHSEAL comparison: REJECTED" in result.stdout


def test_verify_authenticated_runner_rejects_invalid_bundle_without_external_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def external_state_forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline verification must not access external state")

    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_durable_bundle",
        lambda _path: (_ for _ in ()).throw(
            AuthenticatedRunnerDurableBundleError("synthetic invalid durable evidence")
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_default_config",
        lambda _path: _verification_config(),
    )
    for name in ("load_config", "load_operator_secrets", "_budget_and_usage"):
        monkeypatch.setattr(cli_module, name, external_state_forbidden)

    result = RUNNER.invoke(
        cli_module.app,
        [
            "models",
            "verify-authenticated-runner",
            "--bundle",
            str(tmp_path / "invalid.json"),
            "--config",
            str(tmp_path / "default.toml"),
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "synthetic invalid durable evidence" in " ".join(result.stdout.split())


def _rejected_result() -> AuthenticatedRunnerOpenRouterResult:
    successful = _result()
    return AuthenticatedRunnerOpenRouterResult(
        execution=successful.execution,
        runner_evidence=successful.runner_evidence,
        authseal_collision_map=None,
        authseal_decision_projections=(),
        authseal_rejection_kind="EvidenceSealAuthorityError",
    )


def test_authenticated_runner_help_exposes_explicit_operator_inputs() -> None:
    result = RUNNER.invoke(
        cli_module.app,
        ["models", "authenticated-runner", "--help"],
        env={"COLUMNS": "160"},
    )

    assert result.exit_code == 0
    for option in (
        "--secrets-env-file",
        "--candidate-discovery-run",
        "--primary-judge-discovery-run",
        "--replay-judge-discovery-run",
        "--ground-truth-provenance",
        "--cost-ledger",
        "--allow-code-egress",
        "--preflight-only",
        "--runtime-evidence-smoke-bundle",
        "--retry-continuity-config",
    ):
        assert option in result.stdout


def test_authenticated_runner_rejects_implicit_schema_retry_before_other_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(
        execution={
            "max_model_retries": 1,
            "max_schema_validation_retries": 3,
            "max_requests_per_agent": 480,
        }
    )
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("implicit schema retry must reject before other runner inputs")

    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", forbidden)

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, preflight_only=True),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "explicit --retry-continuity-config" in " ".join(result.stdout.split())


def test_authenticated_runner_loads_only_the_explicit_retry_continuity_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SimpleNamespace(
        execution=SimpleNamespace(cost_ledger_path=None),
        effective_reserved_output_tokens=4_096,
    )
    captured: list[tuple[Path, Path]] = []

    def load_continuity(*, default_path: Path, continuity_path: Path) -> object:
        captured.append((default_path, continuity_path))
        return config

    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_retry_continuity_config",
        load_continuity,
    )
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("explicit continuity must not use the ordinary config loader")
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "load_model_benchmark_corpus",
        lambda _path: (_ for _ in ()).throw(ConfigError("stop after continuity load")),
    )

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(
            tmp_path,
            preflight_only=True,
            include_retry_continuity=True,
        ),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "stop after continuity load" in " ".join(result.stdout.split())
    assert captured == [
        (
            tmp_path / "mmaudit.toml",
            tmp_path / "retry-continuity.toml",
        )
    ]


def test_authenticated_runner_budget_factory_binds_exact_cost_and_token_configuration(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    tmp_path.chmod(0o700)
    ledger_path = tmp_path / "cost-ledger.json"
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("250"))
    config = config_factory(
        execution={
            "budget_usd": 250.0,
            "max_output_tokens_per_request": 4_096,
            "max_requests_per_agent": 192,
        },
        token_budgets={
            "reserved_output_tokens": 4_096,
            "global_input_token_budget": 1_234_567,
            "global_output_token_budget": 345_678,
            "per_model_cost_budget_usd": {
                "deepseek/deepseek-v4-pro-0813": 125.25,
            },
            "per_role_cost_budget_usd": {"model_benchmark": 225.5},
        },
    )

    budget, usage = cli_module._budget_and_usage(
        config,
        ledger_path=ledger_path,
        require_endpoint_cost_bound=True,
    )

    assert budget.total_usd == 250.0
    assert budget.atomic_ledger is not None
    assert budget.atomic_ledger.cap_usd == Decimal("250")
    assert budget.require_endpoint_cost_bound is True
    assert budget.max_output_tokens == config.execution.max_output_tokens_per_request
    assert budget.conservative_rate == config.execution.conservative_usd_per_million_tokens
    assert budget.max_requests_per_agent == config.execution.max_requests_per_agent
    assert budget.global_input_token_budget == 1_234_567
    assert budget.global_output_token_budget == 345_678
    assert budget.per_model_usd_caps == {"deepseek/deepseek-v4-pro-0813": Decimal("125.25")}
    assert budget.per_role_usd_caps == {"model_benchmark": Decimal("225.5")}
    assert usage.records == []


def test_authenticated_runner_requires_opt_in_before_loading_or_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(AssertionError("config must not be loaded")),
    )
    monkeypatch.setattr(
        cli_module,
        "load_operator_secrets",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("secret file must not be accessed")
        ),
    )

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, allow_egress=False),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires explicit --allow-code-egress" in " ".join(result.stdout.split())


def test_authenticated_runner_full_admission_rejects_before_ledger_secret_or_output_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SimpleNamespace(
        execution=SimpleNamespace(cost_ledger_path=None),
        effective_reserved_output_tokens=2_048,
    )
    admission_calls: list[dict[str, object]] = []

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_frozen_ground_truth_provenance",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_frozen_ground_truth",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_public_model_lineage",
        lambda: object(),
    )
    monkeypatch.setattr(cli_module, "load_candidate_registry", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (object(), (object(),)),
    )
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: object())
    monkeypatch.setattr(cli_module, "_require_qualification_release_pins", lambda **_kw: None)

    def reject_full_admission(**kwargs: object) -> None:
        admission_calls.append(dict(kwargs))
        raise RoutePredicateRequirementError(
            RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
            (
                RoutePredicateResult(
                    predicate_id=RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION,
                    disposition=RoutePredicateDisposition.UNAVAILABLE,
                    reason=RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE,
                ),
            ),
        )

    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_three_route_admission",
        reject_full_admission,
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError(
            "full route admission must precede ledger, path, secret, execution, and output state"
        )

    for name in (
        "_load_authenticated_runner_smoke_evidence_bundle",
        "build_route_runtime_evidence_artifact",
        "verify_route_runtime_evidence",
        "_selected_cost_ledger_path",
        "_budget_and_usage",
        "_preflight_authenticated_runner_cli_paths",
        "_preflight_authenticated_runner_output",
        "preflight_authenticated_openrouter_launch",
        "select_operator_secret_file",
        "load_operator_secrets",
        "execute_authenticated_openrouter_runner",
        "build_authenticated_runner_durable_bundle",
        "_write_authenticated_runner_output_fresh",
    ):
        monkeypatch.setattr(cli_module, name, forbidden)

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, preflight_only=True),
        env={
            "COLUMNS": "400",
            "MMAUDIT_SECRETS_ENV_FILE": str(tmp_path / "different-secret.env"),
        },
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "route predicate report does not satisfy its closed purpose" in result.stdout
    assert "VALID / NONAUTHORIZING" not in result.stdout
    assert len(admission_calls) == 1
    assert admission_calls[0]["purpose"] is RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION
    assert admission_calls[0]["runtime_evidence"] is None
    assert admission_calls[0]["runtime_required_output_tokens"] == 2_048
    assert not (tmp_path / "cost-ledger.json").exists()
    for name in (
        "primary-campaign",
        "primary-portfolio",
        "replay-campaign",
        "replay-portfolio",
        "runner-evidence.json",
    ):
        assert not (tmp_path / name).exists()


def test_authenticated_runner_runtime_evidence_is_derived_and_passed_through_before_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SimpleNamespace(
        execution=SimpleNamespace(cost_ledger_path=None),
        effective_reserved_output_tokens=2_048,
    )
    policy = object()
    smoke_bundle = object()
    runtime_artifact = object()
    runtime_capability = object()
    ledger = SimpleNamespace(
        path=tmp_path / "cost-ledger.json",
        lock_path=tmp_path / "cost-ledger.json.lock",
    )
    budget = SimpleNamespace(atomic_ledger=ledger)
    events: list[str] = []
    path_calls: list[tuple[Path, ...]] = []
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        cli_module,
        "load_authenticated_runner_retry_continuity_config",
        lambda **_kwargs: config,
    )
    monkeypatch.setattr(
        cli_module,
        "load_config",
        lambda _path: (_ for _ in ()).throw(
            AssertionError("explicit continuity must not use the ordinary config loader")
        ),
    )
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_frozen_ground_truth_provenance",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_frozen_ground_truth",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(cli_module, "resolve_verified_public_model_lineage", object)
    monkeypatch.setattr(cli_module, "load_candidate_registry", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (object(), (object(),)),
    )
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: policy)
    monkeypatch.setattr(cli_module, "_require_qualification_release_pins", lambda **_kw: None)

    def preflight_paths(**kwargs: object) -> None:
        events.append("paths")
        path_calls.append(cast(tuple[Path, ...], kwargs["source_paths"]))

    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_cli_paths",
        preflight_paths,
    )

    def load_smoke(path: Path) -> object:
        events.append("load-smoke")
        assert path == tmp_path / "runtime-smoke-evidence.json"
        return smoke_bundle

    monkeypatch.setattr(
        cli_module,
        "_load_authenticated_runner_smoke_evidence_bundle",
        load_smoke,
    )

    def build_runtime(**kwargs: object) -> object:
        events.append("build-runtime")
        assert kwargs == {
            "smoke_bundle": smoke_bundle,
            "qualification_policy": policy,
        }
        return runtime_artifact

    monkeypatch.setattr(cli_module, "build_route_runtime_evidence_artifact", build_runtime)

    def verify_runtime(artifact: object, qualification_policy: object) -> object:
        events.append("verify-runtime")
        assert artifact is runtime_artifact
        assert qualification_policy is policy
        return runtime_capability

    monkeypatch.setattr(cli_module, "verify_route_runtime_evidence", verify_runtime)

    def admit_routes(**kwargs: object) -> tuple[()]:
        events.append("route-admission")
        captured["admission"] = kwargs
        return ()

    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_three_route_admission",
        admit_routes,
    )

    def select_ledger(_config: object, path: Path | None) -> Path:
        events.append("select-ledger")
        assert path == ledger.path
        return tmp_path / "cost-ledger.json"

    monkeypatch.setattr(cli_module, "_selected_cost_ledger_path", select_ledger)

    def open_ledger(*_args: object, **_kwargs: object) -> tuple[object, object]:
        events.append("open-ledger")
        return budget, object()

    monkeypatch.setattr(cli_module, "_budget_and_usage", open_ledger)
    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_output",
        lambda _path: events.append("output-preflight"),
    )

    def reject_after_launch(launch: AuthenticatedRunnerOpenRouterLaunch) -> object:
        events.append("launch-preflight")
        captured["launch"] = launch
        raise AuthenticatedRunnerExecutionError("stop after runtime evidence launch capture")

    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_openrouter_launch",
        reject_after_launch,
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("runtime evidence preflight must not select secrets or dispatch")

    for name in (
        "select_operator_secret_file",
        "load_operator_secrets",
        "execute_authenticated_openrouter_runner",
        "_write_authenticated_runner_output_fresh",
    ):
        monkeypatch.setattr(cli_module, name, forbidden)

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(
            tmp_path,
            preflight_only=True,
            include_runtime_evidence=True,
            include_retry_continuity=True,
        ),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "stop after runtime evidence launch capture" in " ".join(result.stdout.split())
    assert events == [
        "paths",
        "load-smoke",
        "build-runtime",
        "verify-runtime",
        "route-admission",
        "select-ledger",
        "open-ledger",
        "paths",
        "output-preflight",
        "launch-preflight",
    ]
    admission = cast(dict[str, object], captured["admission"])
    assert admission["runtime_evidence"] is runtime_capability
    launch = cast(AuthenticatedRunnerOpenRouterLaunch, captured["launch"])
    assert launch.runtime_route_evidence is runtime_capability
    runtime_path = tmp_path / "runtime-smoke-evidence.json"
    retry_path = tmp_path / "retry-continuity.toml"
    assert runtime_path in path_calls[0]
    assert retry_path in path_calls[0]
    assert ledger.path not in path_calls[0]
    assert runtime_path in path_calls[1]
    assert retry_path in path_calls[1]
    assert ledger.path in path_calls[1]


def test_authenticated_runner_runtime_evidence_failure_precedes_ledger_and_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = SimpleNamespace(
        execution=SimpleNamespace(cost_ledger_path=None),
        effective_reserved_output_tokens=2_048,
    )
    policy = object()
    events: list[str] = []

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_frozen_ground_truth_provenance",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_frozen_ground_truth",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(cli_module, "resolve_verified_public_model_lineage", object)
    monkeypatch.setattr(cli_module, "load_candidate_registry", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (object(), (object(),)),
    )
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: policy)
    monkeypatch.setattr(cli_module, "_require_qualification_release_pins", lambda **_kw: None)
    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_cli_paths",
        lambda **_kwargs: events.append("paths"),
    )

    def load_smoke(_path: Path) -> object:
        events.append("load-smoke")
        return object()

    monkeypatch.setattr(
        cli_module,
        "_load_authenticated_runner_smoke_evidence_bundle",
        load_smoke,
    )

    def build_runtime(**_kwargs: object) -> object:
        events.append("build-runtime")
        return object()

    monkeypatch.setattr(
        cli_module,
        "build_route_runtime_evidence_artifact",
        build_runtime,
    )

    def reject_runtime(*_args: object, **_kwargs: object) -> object:
        events.append("verify-runtime")
        raise ValueError("runtime evidence verification failed")

    monkeypatch.setattr(cli_module, "verify_route_runtime_evidence", reject_runtime)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("invalid runtime evidence must reject before mutable state")

    for name in (
        "require_authenticated_runner_three_route_admission",
        "_selected_cost_ledger_path",
        "_budget_and_usage",
        "_preflight_authenticated_runner_output",
        "select_operator_secret_file",
        "load_operator_secrets",
        "execute_authenticated_openrouter_runner",
        "_write_authenticated_runner_output_fresh",
    ):
        monkeypatch.setattr(cli_module, name, forbidden)

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, include_runtime_evidence=True),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "runtime evidence verification failed" in " ".join(result.stdout.split())
    assert events == ["paths", "load-smoke", "build-runtime", "verify-runtime"]


@pytest.mark.parametrize(
    ("message", "expected"),
    (
        (
            "runner candidate route lacks required native structured_outputs support",
            "native structured_outputs",
        ),
        (
            "runner candidate route lacks an explicit metadata completion limit",
            "explicit metadata completion limit",
        ),
    ),
)
def test_authenticated_runner_route_eligibility_rejection_precedes_secret_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    message: str,
    expected: str,
) -> None:
    config = SimpleNamespace(
        execution=SimpleNamespace(cost_ledger_path=None),
        effective_reserved_output_tokens=2_048,
    )
    ledger = SimpleNamespace(
        path=tmp_path / "cost-ledger.json",
        lock_path=tmp_path / "cost-ledger.json.lock",
    )
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_frozen_ground_truth_provenance",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_frozen_ground_truth",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_public_model_lineage",
        lambda: object(),
    )
    monkeypatch.setattr(cli_module, "load_candidate_registry", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (object(), (object(),)),
    )
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: object())
    monkeypatch.setattr(cli_module, "_require_qualification_release_pins", lambda **_kw: None)
    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_three_route_admission",
        lambda **_kwargs: (),
    )
    monkeypatch.setattr(
        cli_module,
        "_budget_and_usage",
        lambda *_args, **_kwargs: (
            SimpleNamespace(atomic_ledger=ledger),
            object(),
        ),
    )
    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_cli_paths",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_output",
        lambda _path: None,
    )
    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_openrouter_launch",
        lambda _launch: (_ for _ in ()).throw(AuthenticatedRunnerExecutionError(message)),
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("route-eligibility rejection must precede secret selection")

    for name in (
        "select_operator_secret_file",
        "load_operator_secrets",
        "execute_authenticated_openrouter_runner",
        "_write_authenticated_runner_output_fresh",
    ):
        monkeypatch.setattr(cli_module, name, forbidden)

    result = RUNNER.invoke(cli_module.app, _required_arguments(tmp_path))

    assert result.exit_code == ExitCode.CONFIGURATION
    assert expected in " ".join(result.stdout.split())
    assert not (tmp_path / "runner-evidence.json").exists()


@pytest.mark.parametrize("explicit_secret", (True, False))
@pytest.mark.parametrize("authseal_reject", (False, True))
def test_authenticated_runner_preflights_before_secret_and_writes_only_durable_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    explicit_secret: bool,
    authseal_reject: bool,
) -> None:
    events: list[str] = []
    config = SimpleNamespace(
        stable_hash=lambda: "e" * 64,
        execution=SimpleNamespace(
            cost_ledger_path=None,
            max_model_retries=1,
            max_schema_validation_retries=0,
            model_dump=lambda **_kwargs: {"synthetic": "execution-config"},
        ),
        effective_reserved_output_tokens=2_048,
    )
    suite = object()
    provenance = object()
    ground_truth = object()
    public_lineage = object()
    policy = object()
    candidate_registry = object()
    primary_registry = object()
    replay_registry = object()
    candidate_manifest = object()
    primary_manifest = object()
    replay_manifest = object()
    candidate_evidence = (object(),)
    primary_evidence = (object(),)
    replay_evidence = (object(),)
    ledger = SimpleNamespace(
        path=tmp_path / "cost-ledger.json",
        lock_path=tmp_path / "cost-ledger.json.lock",
    )
    budget = SimpleNamespace(atomic_ledger=ledger)
    usage = object()
    captured: dict[str, Any] = {}

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: suite)
    monkeypatch.setattr(
        cli_module,
        "load_frozen_ground_truth_provenance",
        lambda _path: provenance,
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_frozen_ground_truth",
        lambda **_kwargs: ground_truth,
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_public_model_lineage",
        lambda: public_lineage,
    )

    def load_registry(path: Path) -> object:
        if "primary" in path.name:
            return primary_registry
        if "replay" in path.name:
            return replay_registry
        return candidate_registry

    def load_discovery(path: Path) -> tuple[object, tuple[object, ...]]:
        if "primary" in path.name:
            return primary_manifest, primary_evidence
        if "replay" in path.name:
            return replay_manifest, replay_evidence
        return candidate_manifest, candidate_evidence

    monkeypatch.setattr(cli_module, "load_candidate_registry", load_registry)
    monkeypatch.setattr(cli_module, "load_model_discovery_run", load_discovery)
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: policy)
    monkeypatch.setattr(cli_module, "_require_qualification_release_pins", lambda **_kw: None)

    def admit_routes(**kwargs: object) -> tuple[()]:
        assert kwargs["runtime_required_output_tokens"] == 2_048
        events.append("route-admission")
        return ()

    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_three_route_admission",
        admit_routes,
    )
    monkeypatch.setattr(
        cli_module,
        "_budget_and_usage",
        lambda *_args, **_kwargs: (budget, usage),
    )

    def preflight_paths(**kwargs: object) -> None:
        events.append("paths")
        captured["source_paths"] = kwargs["source_paths"]

    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_cli_paths",
        preflight_paths,
    )
    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_output",
        lambda _path: events.append("output-preflight"),
    )

    def preflight(launch: AuthenticatedRunnerOpenRouterLaunch) -> object:
        events.append("launch-preflight")
        captured["launch"] = launch
        return object()

    monkeypatch.setattr(cli_module, "preflight_authenticated_openrouter_launch", preflight)

    def select_secret(path: Path | None) -> Path:
        events.append("select-secret")
        if explicit_secret:
            assert path == tmp_path / "operator-secrets.env"
        else:
            assert path is None
        return tmp_path / "operator-secrets.env"

    monkeypatch.setattr(cli_module, "select_operator_secret_file", select_secret)

    def load_secrets(path: Path | None, *, required: bool) -> _SecretPresenceOnly:
        events.append("secret")
        assert path == tmp_path / "operator-secrets.env"
        assert required is True
        return _SecretPresenceOnly()

    monkeypatch.setattr(cli_module, "load_operator_secrets", load_secrets)

    async def execute_runner(**kwargs: object) -> AuthenticatedRunnerOpenRouterResult:
        events.append("execute")
        captured.update(kwargs)
        return _rejected_result() if authseal_reject else _result()

    monkeypatch.setattr(cli_module, "execute_authenticated_openrouter_runner", execute_runner)

    durable_bundle = _durable_bundle()

    def build_bundle(**kwargs: object) -> AuthenticatedRunnerDurableEvidenceBundle:
        events.append("bundle")
        captured["bundle_inputs"] = kwargs
        return durable_bundle

    monkeypatch.setattr(cli_module, "build_authenticated_runner_durable_bundle", build_bundle)

    durable_binding: dict[str, object] = {}
    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_durable_config_binding",
        lambda supplied, **kwargs: durable_binding.update(kwargs) or supplied,
    )

    def write_output(path: Path, value: AuthenticatedRunnerDurableEvidenceBundle) -> int:
        events.append("write")
        captured["output_path"] = path
        captured["output"] = value
        return 1

    monkeypatch.setattr(cli_module, "_write_authenticated_runner_output_fresh", write_output)

    result = RUNNER.invoke(
        cli_module.app,
        _required_arguments(tmp_path, include_secret_file=explicit_secret),
        env=(
            {"MMAUDIT_SECRETS_ENV_FILE": ""}
            if explicit_secret
            else {"MMAUDIT_SECRETS_ENV_FILE": str(tmp_path / "operator-secrets.env")}
        ),
    )

    if authseal_reject:
        assert result.exit_code == ExitCode.CONFIGURATION
        assert "nonauthorizing runner evidence was retained" in " ".join(result.stdout.split())
    else:
        assert result.exit_code == 0, result.stdout
    assert events == [
        "route-admission",
        "paths",
        "output-preflight",
        "launch-preflight",
        "select-secret",
        "paths",
        "secret",
        "execute",
        "bundle",
        "output-preflight",
        "write",
    ]
    launch = cast(AuthenticatedRunnerOpenRouterLaunch, captured["launch"])
    assert launch.explicitly_allow_synthetic_egress is True
    assert launch.run_plans[0].candidate_declared_cost_cap_usd_per_attempt.as_tuple().exponent == -2
    assert launch.run_plans[1].judge_declared_cost_cap_usd_per_attempt.as_tuple().exponent == -2
    assert captured["operator_secrets"].openrouter_api_key_present is True
    assert tmp_path / "operator-secrets.env" in captured["source_paths"]
    assert captured["output"] is durable_bundle
    bundle_inputs = cast(dict[str, object], captured["bundle_inputs"])
    assert set(bundle_inputs) == {
        "effective_config_sha256",
        "runner_evidence",
        "candidate_cost_plans",
        "judge_cost_plans",
        "candidate_reports",
        "prepared_runs",
        "adjudication_reports",
        "authseal_collision_map",
        "authseal_decision_projections",
        "authseal_rejection_kind",
    }
    assert bundle_inputs["effective_config_sha256"] == "e" * 64
    assert "EXECUTION-CAPABILITY-CANARY" not in repr(bundle_inputs)
    assert durable_binding["effective_config_sha256"] == "e" * 64
    assert durable_binding["maximum_attempts_per_logical_request"] == 2
    assert durable_binding["model_retry_policy_sha256"] == (
        cli_module.ModelRetryPolicy.build(
            transient_retry_limit=1,
            schema_validation_retry_limit=0,
        ).policy_sha256
    )


def test_authenticated_runner_budget_drift_rejects_before_secret_selection_or_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "cost-ledger.json",
        cap_usd=Decimal("250"),
    )
    before = ledger.snapshot()
    config = SimpleNamespace(
        execution=SimpleNamespace(cost_ledger_path=None),
        token_budgets=SimpleNamespace(global_input_token_budget=8_000_000),
        effective_reserved_output_tokens=2_048,
    )
    budget = SimpleNamespace(
        atomic_ledger=ledger,
        global_input_token_budget=None,
    )
    events: list[str] = []

    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(cli_module, "load_model_benchmark_corpus", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_frozen_ground_truth_provenance",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        cli_module,
        "resolve_verified_frozen_ground_truth",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(cli_module, "resolve_verified_public_model_lineage", object)
    monkeypatch.setattr(cli_module, "load_candidate_registry", lambda _path: object())
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda _path: (object(), (object(),)),
    )
    monkeypatch.setattr(cli_module, "load_qualification_policy", lambda _path: object())
    monkeypatch.setattr(cli_module, "_require_qualification_release_pins", lambda **_kw: None)
    monkeypatch.setattr(
        cli_module,
        "require_authenticated_runner_three_route_admission",
        lambda **_kwargs: (),
    )
    monkeypatch.setattr(
        cli_module,
        "_budget_and_usage",
        lambda *_args, **_kwargs: (budget, object()),
    )
    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_cli_paths",
        lambda **_kwargs: events.append("paths"),
    )
    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_output",
        lambda _path: events.append("output-preflight"),
    )

    def reject_drift(launch: AuthenticatedRunnerOpenRouterLaunch) -> object:
        events.append("launch-preflight")
        assert launch.budget.global_input_token_budget is None
        assert launch.config.token_budgets.global_input_token_budget == 8_000_000
        assert ledger.snapshot() == before
        raise AuthenticatedRunnerExecutionError(
            "runner shared budget global input token budget differs from configuration"
        )

    monkeypatch.setattr(
        cli_module,
        "preflight_authenticated_openrouter_launch",
        reject_drift,
    )

    def forbidden(*_args: object, **_kwargs: object) -> object:
        events.append("forbidden")
        raise AssertionError("budget drift must reject before secret selection or execution")

    monkeypatch.setattr(cli_module, "select_operator_secret_file", forbidden)
    monkeypatch.setattr(cli_module, "load_operator_secrets", forbidden)
    monkeypatch.setattr(cli_module, "execute_authenticated_openrouter_runner", forbidden)

    result = RUNNER.invoke(cli_module.app, _required_arguments(tmp_path))

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "runner shared budget global input token budget differs from configuration" in " ".join(
        result.stdout.split()
    )
    assert events == ["paths", "output-preflight", "launch-preflight"]
    assert ledger.snapshot() == before


def test_authenticated_runner_cli_path_preflight_rejects_output_inside_source() -> None:
    root = Path("/private/tmp/mmaudit-authrunner-cli-path-test")
    source = root / "candidate-discovery"

    with pytest.raises(ConfigError, match="overlaps immutable input"):
        cli_module._preflight_authenticated_runner_cli_paths(
            mutable_outputs=(
                source / "campaign",
                root / "primary-portfolio",
                root / "replay-campaign",
                root / "replay-portfolio",
                root / "runner-evidence.json",
            ),
            source_paths=(source,),
        )


def test_authenticated_runner_output_preflight_requires_fresh_private_leaf(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"

    cli_module._preflight_authenticated_runner_output(output)
    output.write_text("occupied\n", encoding="utf-8")
    output.chmod(0o600)
    with pytest.raises(ConfigError, match="must be fresh"):
        cli_module._preflight_authenticated_runner_output(output)


def test_authenticated_runner_output_preflight_exercises_hard_link_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"

    def reject_link(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("synthetic hard-link rejection")

    monkeypatch.setattr(cli_module.os, "link", reject_link)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        cli_module.os.supports_dir_fd | {reject_link},
    )
    monkeypatch.setattr(
        cli_module.os,
        "supports_follow_symlinks",
        cli_module.os.supports_follow_symlinks | {reject_link},
    )

    with pytest.raises(ConfigError, match="unavailable, linked, or not writable"):
        cli_module._preflight_authenticated_runner_output(output)

    assert not output.exists()


def test_authenticated_runner_output_publication_is_fresh_private_and_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"
    bundle = _durable_bundle()
    payload = b'{"bundle_sha256":"' + (b"e" * 64) + b'","serialized_authority":false}'
    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_durable_bundle_bytes",
        lambda value: payload if value is bundle else b"wrong",
    )

    written = cli_module._write_authenticated_runner_output_fresh(output, bundle)

    assert written == output.stat().st_size
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.read_bytes() == payload


def test_authenticated_runner_output_publication_never_clobbers_intervening_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"
    original_preflight = cli_module._preflight_authenticated_runner_output
    bundle = _durable_bundle()
    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_durable_bundle_bytes",
        lambda value: b"{}" if value is bundle else b"wrong",
    )

    def racing_preflight(path: Path) -> None:
        original_preflight(path)
        output.write_text("operator-owned\n", encoding="utf-8")
        output.chmod(0o600)

    monkeypatch.setattr(
        cli_module,
        "_preflight_authenticated_runner_output",
        racing_preflight,
    )

    with pytest.raises(ConfigError, match="must remain fresh"):
        cli_module._write_authenticated_runner_output_fresh(
            output,
            bundle,
        )

    assert output.read_text(encoding="utf-8") == "operator-owned\n"


def test_authenticated_runner_output_publication_rejects_parent_namespace_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    moved = tmp_path / "moved-private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"
    bundle = _durable_bundle()
    real_link = cli_module.os.link

    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_durable_bundle_bytes",
        lambda value: b"{}" if value is bundle else b"wrong",
    )
    monkeypatch.setattr(cli_module, "_preflight_authenticated_runner_output", lambda _path: None)

    def move_parent_after_link(*args: object, **kwargs: object) -> None:
        real_link(*args, **kwargs)
        private.rename(moved)

    monkeypatch.setattr(cli_module.os, "link", move_parent_after_link)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        cli_module.os.supports_dir_fd | {move_parent_after_link},
    )
    monkeypatch.setattr(
        cli_module.os,
        "supports_follow_symlinks",
        cli_module.os.supports_follow_symlinks | {move_parent_after_link},
    )

    with pytest.raises(ConfigError, match="publication failed safely"):
        cli_module._write_authenticated_runner_output_fresh(output, bundle)

    assert not output.exists()
    assert (moved / output.name).read_bytes() == b"{}"


def test_authenticated_runner_output_rollback_never_deletes_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    moved = tmp_path / "moved-private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    output = private / "runner-evidence.json"
    bundle = _durable_bundle()
    real_link = cli_module.os.link

    monkeypatch.setattr(
        cli_module,
        "authenticated_runner_durable_bundle_bytes",
        lambda value: b"{}" if value is bundle else b"wrong",
    )
    monkeypatch.setattr(cli_module, "_preflight_authenticated_runner_output", lambda _path: None)

    def replace_after_parent_move(*args: object, **kwargs: object) -> None:
        real_link(*args, **kwargs)
        private.rename(moved)
        replacement = moved / output.name
        replacement.unlink()
        replacement.write_text("operator-owned\n", encoding="utf-8")
        replacement.chmod(0o600)

    monkeypatch.setattr(cli_module.os, "link", replace_after_parent_move)
    monkeypatch.setattr(
        cli_module.os,
        "supports_dir_fd",
        cli_module.os.supports_dir_fd | {replace_after_parent_move},
    )
    monkeypatch.setattr(
        cli_module.os,
        "supports_follow_symlinks",
        cli_module.os.supports_follow_symlinks | {replace_after_parent_move},
    )

    with pytest.raises(ConfigError, match="publication failed safely"):
        cli_module._write_authenticated_runner_output_fresh(output, bundle)

    assert not output.exists()
    assert (moved / output.name).read_text(encoding="utf-8") == "operator-owned\n"


def test_authenticated_runner_cost_ledger_override_must_match_configured_path(
    tmp_path: Path,
) -> None:
    configured = (tmp_path / "configured-ledger.json").resolve()
    override = (tmp_path / "other-ledger.json").resolve()
    config = SimpleNamespace(
        execution=SimpleNamespace(cost_ledger_path=str(configured)),
    )

    with pytest.raises(ConfigError, match="differs from configured ledger"):
        cli_module._selected_cost_ledger_path(cast(Any, config), override)


def test_async_cli_preserves_bracketed_rejection_text_verbatim(
    capsys: pytest.CaptureFixture[str],
) -> None:
    async def reject() -> None:
        raise ConfigError("[bold]endpoint[/bold]")

    with pytest.raises(typer.Exit):
        cli_module._run_async_cli(reject)

    assert "[bold]endpoint[/bold]" in capsys.readouterr().out


@pytest.mark.parametrize("rejected", [False, True], ids=["complete", "rejected"])
def test_authenticated_runner_durable_output_delegates_exact_retained_runs(
    monkeypatch: pytest.MonkeyPatch,
    rejected: bool,
) -> None:
    result = _rejected_result() if rejected else _result()
    expected = _durable_bundle()
    observed: dict[str, object] = {}

    def build(**kwargs: object) -> AuthenticatedRunnerDurableEvidenceBundle:
        observed.update(kwargs)
        return expected

    monkeypatch.setattr(cli_module, "build_authenticated_runner_durable_bundle", build)

    output = cli_module._authenticated_runner_durable_output(result)

    assert output is expected
    assert observed["runner_evidence"] is result.runner_evidence
    assert observed["candidate_cost_plans"] == (
        "candidate-cost-plan-0",
        "candidate-cost-plan-1",
    )
    assert observed["judge_cost_plans"] == (
        "judge-cost-plan-0",
        "judge-cost-plan-1",
    )
    assert observed["candidate_reports"] == (
        "candidate-report-0",
        "candidate-report-1",
    )
    assert observed["prepared_runs"] == ("prepared-0", "prepared-1")
    assert observed["adjudication_reports"] == (
        "adjudication-report-0",
        "adjudication-report-1",
    )
    assert observed["authseal_collision_map"] is result.authseal_collision_map
    assert observed["authseal_decision_projections"] == result.authseal_decision_projections
    assert observed["authseal_rejection_kind"] == result.authseal_rejection_kind
    assert observed["effective_config_sha256"] == "e" * 64
    assert "EXECUTION-CAPABILITY-CANARY" not in repr(observed)
